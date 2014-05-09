{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
The EAX mode of operation, as described in 
<http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf>.
EAX is a mode of operation for block ciphers, which provides confidentiality 
and integrity of the transmitted data. EAX is provably secure under a standard 
complexity-theoretic assumption.
-}

module Crypto.Mode.EAX (EAXContext(..), Cipher(..), eaxEncrypt, eaxDecrypt,
                        blockToInt, intToBlock)
where

import Data.ByteString hiding (map, length, zip, replicate, take, drop)
import qualified GHC.Word
import qualified Data.ByteString as B
import Data.Bits as Bits

-- |The EAX context.
data EAXContext = 
   EAXContext { taglen :: Int, -- ^ Length of the authentication tag in bytes
                cipher :: Cipher, -- ^ The underlying cipher
                nonce :: Integer  -- ^ The current nonce
              } 

-- |A generic representation of a block cipher in ECB mode.
data Cipher = 
   Cipher { blockLen :: Int, -- ^ Block length in bytes
            encryptOp :: ByteString -> ByteString, -- ^ The encryption function
            decryptOp :: ByteString -> ByteString -- ^ The decryption function
          } 

_nul :: GHC.Word.Word8
_nul = fromIntegral (0 :: Int)
_128 :: GHC.Word.Word8
_128 = fromIntegral (128 :: Int)

xorBlock :: ByteString -> ByteString -> ByteString
xorBlock a b | (B.length a) /= (B.length b) = error "Invalid length in XOR"
             | otherwise = pack $ (B.zipWith xor a b)

xorAtEnd :: ByteString -> ByteString -> ByteString
xorAtEnd a b | (B.length a) < (B.length b) = xorAtEnd b a
             | otherwise = let (x, y) = B.splitAt (B.length a - B.length b) a
                           in append x (y `xorBlock` b)

intToBlock :: Int -> Integer -> ByteString
intToBlock 0 value = intToBlock' empty value
intToBlock desiredBlockLen value =
   {-# SCC "int2block" #-}
   let b = intToBlock' empty value
   in if (B.length b <= desiredBlockLen)
         then append (B.replicate (desiredBlockLen - (B.length b)) _nul) b
         else error "Cannot convert to block"

intToBlock' :: ByteString -> Integer -> ByteString
intToBlock' curBlock 0 = curBlock
intToBlock' curBlock value =
   let low = fromIntegral $ value .&. 255 
   in intToBlock' (B.cons low curBlock) (value `shift` (-8))

blockToInt :: ByteString -> Integer
blockToInt = 
   {-# SCC "block2int" #-}
   B.foldl (\x y -> x * 256 + (fromIntegral y)) 0

-- Count from 0
getBlock :: Int -> Int -> ByteString -> ByteString
getBlock i len msg = B.take len (B.drop (i*len) msg)

cbcMac :: Cipher -> ByteString -> ByteString
cbcMac c msg | (B.length msg `mod` (blockLen c)) /= 0 = error "Bad msg length"
             | otherwise = cbc' ((B.length msg) `div` (blockLen c)) c msg

cbc' :: Int -> Cipher -> ByteString -> ByteString
cbc' 0 c _ = B.replicate (blockLen c) _nul
cbc' i c msg = 
   let lastC = cbc' (i-1) c msg
       block = getBlock (i-1) (blockLen c) msg
   in (encryptOp c) (lastC `xorBlock` block)

ctrEncrypt :: Cipher -> Integer -> ByteString -> (ByteString, Integer)
ctrEncrypt c n msg =
   {-# SCC "ctrencrypt" #-}
   let blockL = blockLen c
       msgLen = B.length msg 
       nend = n + fromIntegral ((msgLen + blockL - 1) `div` blockL)
       keyStream = B.take msgLen $ B.concat $
                       map ((encryptOp c) . (intToBlock blockL)) [n..nend]
   in (keyStream `xorBlock` msg, nend)

pad :: Cipher -> ByteString -> ByteString -> ByteString -> ByteString
pad c msg b p | B.length msg `mod` (blockLen c) == 0 = xorAtEnd msg b
              | otherwise =
                  let blen    = (blockLen c)
                      mlen    = B.length msg
                      padding = cons _128 
                                     (B.replicate (blen - 1 - (mlen `mod` blen)) 
                                                  _nul)
                  in (append msg padding) `xorAtEnd` p

omac :: Cipher -> Integer -> ByteString -> ByteString
omac c t msg =
   omac' c (append (intToBlock (blockLen c) t) msg)

omac' :: Cipher -> ByteString -> ByteString
omac' c msg =
   let l = (encryptOp c) (B.replicate (blockLen c) _nul)
       b = doubleString (blockLen c) l
       p = doubleString (blockLen c) b
       padded = pad c msg b p
   in cbcMac c padded

doubleString :: Int -> ByteString -> ByteString
doubleString blen input = let choice = input `B.index` 0 < _128
                              di = dub input
                          in
                          if choice
                           then di `xorAtEnd` (zeroBytes blen)
                           else di `xorAtEnd` (gfPoly blen)
   where dub block = intToBlock blen $ ((blockToInt block) `shift` 1) .&. 
                                       (2^(8*blen) - 1)

gfPoly :: Int -> ByteString
gfPoly    16 = cons (fromIntegral (135 :: Int)) empty -- gf(2^128) poly
gfPoly    x  = error $ "No GF polynomial defined for block length " ++ show x

zeroBytes :: Int -> ByteString
zeroBytes 16 = cons (fromIntegral (0 :: Int)) empty
zeroBytes x  = error $ "No GF polynomial defined for block length " ++ show x

-- |Encrypt data in EAX mode.
eaxEncrypt :: EAXContext -- ^ The current EAX context
              -> ByteString -- ^ An optional header - won't be encrypted, but 
                            -- will be authenticated. Not included in the 
                            -- result!
              -> ByteString -- ^ The message - will be encrypted and 
                            -- authenticated
              -> (ByteString, EAXContext) -- ^ The resulting cipher text and a 
                                          -- new EAX context
eaxEncrypt ctx header msg =
   {-# SCC "encrypt" #-}
   let c = cipher ctx
       oldNonce = nonce ctx
       n = omac c 0 (intToBlock 0 $ nonce ctx)
       h = omac c 1 header
       crypt  = fst $ ctrEncrypt c (blockToInt n) msg
       crypt' = omac c 2 crypt
       tag = (n `xorBlock` crypt') `xorBlock` h
       t = B.take (taglen ctx) tag
   --in (append crypt t, ctx {nonce = oldNonce + 1})
   in (append crypt t, ctx {nonce = oldNonce + 1})

splitLast :: Int -> ByteString -> (ByteString, ByteString)
splitLast n input = B.splitAt (B.length input - n) input

-- |Decrypt data in EAX mode.
eaxDecrypt :: EAXContext -- ^ The current EAX context
              -> ByteString -- ^ An optional header containing additional 
                            -- authenticated information
              -> ByteString -- ^ The encrypted and authenticated message
              -> (Maybe ByteString, EAXContext) -- ^ The plain text and a new 
                                                -- EAX context
eaxDecrypt ctx hdr enc 
   | B.length enc < (taglen ctx) = (Nothing, ctx)
   | otherwise =
      let (crypt, t) = splitLast (taglen ctx) enc
          c = cipher ctx
          n = omac c 0 (intToBlock 0 $ nonce ctx)
          h = omac c 1 hdr
          crypt' = omac c 2 crypt
          tag' = (n `xorBlock` crypt') `xorBlock` h
          t' = B.take (taglen ctx) tag'
      in if t' /= t
            then (Nothing, ctx)
            else (Just $ fst $ ctrEncrypt c (blockToInt n) crypt, 
                  ctx {nonce = (nonce ctx) + 1})

{- Test values

import Crypto.Cipher.AES

k' = intToBlock 16 0x8395FCF1E95BEBD697BD010BC766AAC3
n' = 0x22E7ADD93CFC6393C57EC0B3C17D6B44
hdr' = intToBlock 8 0x126735FCC320D25A
m' = intToBlock 21 0xCA40D7446E545FFAED3BD12A740A659FFBBB3CEAB7

testAES = AES.initAES k'
aesEnc = AES.encryptECB testAES
aesDec = AES.decryptECB testAES

testCipher = Cipher {blockLen = 16, encryptOp = aesEnc, decryptOp = aesDec}
testCtx = EAXContext {taglen = 16, cipher = testCipher, nonce = n'}

-}
