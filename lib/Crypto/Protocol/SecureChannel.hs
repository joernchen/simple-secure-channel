{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
This module implements an abstration of a communication channel. Two particular
communication channel instances are provided: RawChannel and SecureChannel. A
RawChannel is a communication channel based on regular Handles. A SecureChannel
adds a cryptographic layer, which provides confidentiality and authenticity of
the transmitted messages.
-}

module Crypto.Protocol.SecureChannel
   (CommunicationChannel(..), RawChannel(..), SecureChannel(..), 
    buildSecureChannelTF, buildSecureChannelAES, runChannel, evalChannel, 
    handleToChannel, handlesToChannel)
where

import Crypto.Mode.EAX
import Codec.Encryption.Twofish as TF
import System.IO
import Data.LargeWord
import qualified Data.ByteString as B
import Control.Monad.State
import Data.ByteString as BS
import Data.ByteString.Char8 (pack, break, unpack)
import qualified Crypto.Cipher.AES as AES

lenLenField :: Int
lenLenField = 3

-- |A stateful communication channel.
class CommunicationChannel a where
   -- |Send a ByteString to the channel
   send        :: ByteString -> StateT a IO ()
   -- |Receive a ByteString of length n from the channel (blocking)
   recv        :: Int -> StateT a IO ByteString 
   -- |Receive a ByteString of length <= n from the channel (blocking)
   recvSome    :: Int -> StateT a IO ByteString 
   -- |Read a line from the channel
   chanGetLine :: StateT a IO String
   -- |Write a line to the channel
   chanPutStrLn :: String -> StateT a IO ()
   chanPutStrLn x = send $ Data.ByteString.Char8.pack (x ++ "\n")

-- |A simple channel, based on two Handles. No encryption is involved here.
data RawChannel = RawChannel { sendHandle :: Handle,
                               recvHandle :: Handle
                             }

-- |Convert a single Handle (like a socket) to a RawChannel
handleToChannel :: Handle -> RawChannel
handleToChannel h = RawChannel { sendHandle = h, recvHandle = h }
-- |Convert two Handles (like stdin and stdout) to a RawChannel
handlesToChannel :: Handle -- ^The Handle for sending data
                    -> Handle -- ^The Handle for receiving data
                    -> RawChannel -- ^The resulting RawChannel
handlesToChannel sendH recvH = RawChannel { 
                                   sendHandle = sendH
                                 , recvHandle = recvH 
                               }

-- |A secure channel. This channel provides confidentiality and authenticity of
-- the transmitted data.
data SecureChannel = 
   SecureChannel { sendEax :: EAXContext,
                   recvEax :: EAXContext,
                   channel :: RawChannel,
                   recvBuf :: ByteString
                 }

instance CommunicationChannel RawChannel where
   send stuff = do
      chan <- get
      lift $ BS.hPut (sendHandle chan) stuff

   recv bytes = do
      chan <- get
      x <- lift $ BS.hGet (recvHandle chan) bytes
      if BS.length x == 0
         then error "Socket closed."
         else return x

   chanGetLine = do
      chan <- get
      lift $ System.IO.hGetLine (recvHandle chan)

   recvSome bytes = do
      chan <- get
      x <- lift $ BS.hGetSome (recvHandle chan) bytes
      if BS.length x == 0
         then error "Socket closed."
         else return x

instance CommunicationChannel SecureChannel where
   send stuff = do
      eaxChan <- get
      let (encrypted, ctx') = myEncrypt (sendEax eaxChan) stuff
      put eaxChan {sendEax = ctx'}
      lift $ BS.hPut (sendHandle $ channel eaxChan) encrypted

   recv = recv' False
   recvSome = recv' True

   chanGetLine = do
      eaxChan <- get
      let rBuf = recvBuf eaxChan
      let (line, rest) = Data.ByteString.Char8.break (=='\n') rBuf
      if line == rBuf
         then do
               recvOne
               chanGetLine
         else do
               put eaxChan {recvBuf = BS.drop 1 rest}
               return $ Data.ByteString.Char8.unpack line

-- |Run a communication function in a channel, similar to runStateT.
runChannel :: (CommunicationChannel a) => StateT a IO b -> a -> IO (b, a)
runChannel commFunction chan = runStateT commFunction chan

-- |Evaluate a communication function in a channel, similar to evalStateT.
evalChannel :: (CommunicationChannel a) => StateT a IO b -> a -> IO b
evalChannel commFunction chan = evalStateT commFunction chan

-- |Build a Twofish256-EAX-secured channel with 16 bytes authentication tags
buildSecureChannelTF :: ByteString -- ^ Cryptographic key for sending
                      -> ByteString -- ^ Cryptographic key for receiving
                      -> RawChannel -- ^ A raw channel to be secured. The raw 
                                    -- channel may not be used afterwards.
                      -> SecureChannel -- ^ The resulting secure channel
buildSecureChannelTF sendKey recvKey rawChannel =
   let scip = TF.mkStdCipher $ (fromIntegral $ blockToInt sendKey :: Word256)
       rcip = TF.mkStdCipher $ (fromIntegral $ blockToInt recvKey :: Word256)
       rdec = intToBlock 16 . fromIntegral . TF.encrypt rcip . fromIntegral . 
              blockToInt
       senc = intToBlock 16 . fromIntegral . TF.encrypt scip . fromIntegral . 
              blockToInt
       sendCipher = Cipher { blockLen = 16, encryptOp = senc, decryptOp = senc }
       recvCipher = Cipher { blockLen = 16, encryptOp = rdec, decryptOp = rdec }
       seax = EAXContext { taglen = 16, cipher = sendCipher, nonce = 1 }
       reax = EAXContext { taglen = 16, cipher = recvCipher, nonce = 1 }
   in SecureChannel { 
          sendEax = seax
        , recvEax = reax
        , channel = rawChannel
        , recvBuf = BS.empty 
      }

-- |Build an AES128-EAX-secured channel with 16 bytes authentication tags
buildSecureChannelAES :: ByteString -- ^ Cryptographic key for sending
                      -> ByteString -- ^ Cryptographic key for receiving
                      -> RawChannel -- ^ A raw channel to be secured. The raw 
                                    -- channel may not be used afterwards.
                      -> SecureChannel -- ^ The resulting secure channel
buildSecureChannelAES sendKey recvKey rawChannel =
   let saes = AES.encryptECB $ AES.initAES sendKey
       raes = AES.encryptECB $ AES.initAES recvKey
       sendCipher = Cipher { blockLen = 16, encryptOp = saes, decryptOp = saes }
       recvCipher = Cipher { blockLen = 16, encryptOp = raes, decryptOp = raes }
       seax = EAXContext { taglen = 16, cipher = sendCipher, nonce = 1 }
       reax = EAXContext { taglen = 16, cipher = recvCipher, nonce = 1 }
   in SecureChannel { 
           sendEax = seax
         , recvEax = reax
         , channel = rawChannel
         , recvBuf = BS.empty 
      }

packetize :: ByteString -> ByteString
packetize msg =
   let lenField = intToBlock lenLenField $ fromIntegral $ B.length msg
   in B.append lenField msg

myEncrypt :: EAXContext -> ByteString -> (ByteString, EAXContext)
myEncrypt ctx plain = 
   let (out, ctx') = eaxEncrypt ctx BS.empty plain
   in (packetize out, ctx')

myDecrypt :: EAXContext -> ByteString -> (Maybe ByteString, EAXContext)
myDecrypt ctx = eaxDecrypt ctx BS.empty

unpacketize :: Handle -> IO ByteString
unpacketize handle = do
   lenField <- BS.hGet handle lenLenField
   if BS.length lenField == 0
      then error "Socket closed."
      else do
            x <- BS.hGet handle (fromIntegral $ blockToInt lenField)
            if BS.length x == 0
               then error "Socket closed."
               else return x

recv' :: Bool -> Int -> StateT SecureChannel IO ByteString
recv' getLess amount = do
   eaxChan <- get
   let rBuf = recvBuf eaxChan
   let amount' = if getLess
                  then 1
                  else amount
   if BS.length rBuf >= amount'
      then do
         let (x, y) = BS.splitAt amount rBuf
         put eaxChan {recvBuf = y}
         return x
      else do
         recvOne
         recv' getLess amount

recvOne :: StateT SecureChannel IO ()
recvOne = do
   eaxChan <- get
   let rBuf = recvBuf eaxChan
   contents <- lift $ unpacketize (recvHandle $ channel $ eaxChan)
   let (Just plain, ctx') = myDecrypt (recvEax eaxChan) contents
   put eaxChan {recvBuf = (append rBuf plain), recvEax = ctx'}
