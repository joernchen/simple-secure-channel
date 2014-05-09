{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
This module implements some convenience functions for executing the J-PAKE key
exchange protocol.
-}

module Crypto.Protocol.SecureChannel.KeyExchange
   (authenticate, deriveKeys, authenticate')
where

import Crypto.Protocol.JPAKE
import Crypto.Protocol.JPAKE.Groups
import Crypto.Util.CredentialsProvider
import Crypto.Util.Encoding
import Crypto.Random
import Crypto.Random.DRBG
import Crypto.Hash.SHA256 (hashlazy)
import qualified Crypto.Hash.SHA256 as SHA
import Data.ByteString.Lazy (fromChunks)
import qualified Data.ByteString.Lazy as L
import Data.ByteString.Lazy.Char8 (pack)
import Data.ByteString hiding (pack)
import qualified Data.ByteString.Char8 as S
import Data.Maybe
import Crypto.Protocol.SecureChannel
import Control.Monad.State
import System.Log.Logger

defaultGroup :: JPAKEGroup ModPGroup
defaultGroup = rfc5114_modp_2048_256

logDebug :: String -> IO ()
logDebug = debugM "Crypto.Protocol.SecureChannel.KeyExchange"

toLazy :: ByteString -> L.ByteString
toLazy = fromChunks . (:[])

toStrict :: L.ByteString -> ByteString
toStrict = fromMaybe Data.ByteString.empty . listToMaybe . L.toChunks

hashlazy' :: L.ByteString -> L.ByteString
hashlazy' x = fromChunks [hashlazy x]

hashstrict :: ByteString -> ByteString
hashstrict = SHA.hash

binToInt :: ByteString -> Integer
binToInt = Data.ByteString.foldl ( \x y -> x * 256 + (fromIntegral y)) 0

initializeSecret :: (MultGroup a, CryptoRandomGen g) => 
                       g 
                    -> (JPAKEGroup a) 
                    -> String 
                    -> String 
                    -> (JPAKESecret a, g)
initializeSecret rng g myName' hisName' =
   let len = (round $ (logBase 2 (fromIntegral $ subgroupOrder $ 
                                  jpakeGroupGenerator $ g) :: Double)) `div` 8
       Right (s1', g1) = genBytes len rng
       Right (s2', g2) = genBytes len g1
       Right (v1', g3) = genBytes len g2
       Right (v2', g4) = genBytes len g3
       Right (v3', g5) = genBytes len g4
       jps = JPAKESecret {secret1 = binToInt s1', secret2 = binToInt s2',
                   myName = myName', hash = hashlazy', v1 = binToInt v1',
                   v2 = binToInt v2', v3 = binToInt v3', 
                   myGen = (jpakeGroupGenerator g),
                   hisName = hisName', password = pack ""}
   in (jps, g5)

-- Explicit key confirmation using a ZKP scheme
confirmKey :: (CommunicationChannel a, MultGroup b, Read b, CryptoRandomGen g)=> 
                 (JPAKEGroup b) 
              -> String 
              -> String 
              -> g
              -> ByteString 
              -> StateT a IO (Bool, g)
confirmKey g myName' hisName' rng k = do
   let len = (round $ (logBase 2 (fromIntegral $ subgroupOrder $ 
                                  jpakeGroupGenerator $ g) :: Double)) `div` 8
   let x = binToInt k
   let Right (v, rng') = genBytes len rng
   let zkp = buildDLZKP (jpakeGroupGenerator g) x (binToInt v) myName' hashlazy'
   lift $ logDebug $ "Sending key confirmation: " ++ (show zkp)
   chanPutStrLn $ show zkp
   msg <- chanGetLine
   lift $ logDebug $ "Got remote key confirmation: " ++ (msg)
   let hisZKP = read msg 
   let itsHim = signerID hisZKP == hisName'
   let correctKey = (expValue hisZKP) == (expValue zkp)
   let correctGen = (generator hisZKP) == (generator zkp)
   return (itsHim && correctGen && correctKey && (verifyDLZKP hashlazy' hisZKP), 
           rng')

-- |Takes the shared master key and derives two individual keys. One for
-- sending, one for receiving.
deriveKeys :: ByteString -- ^ The master key 
              -> String -- ^ Our name
              -> String -- ^ The peer's name
              -> (ByteString, ByteString) -- ^ (our sending key, our 
                                          -- receiving key)
deriveKeys master us them =
   let ourSendingKey   = hashstrict $ append (S.pack us) master
       theirSendingKey = hashstrict $ append (S.pack them) master
   in (ourSendingKey, theirSendingKey)

-- |Perform authentication against a service. After authentication, both parties
-- will have a shared session key, which can be used to establish a secure
-- channel.
authenticate :: (CommunicationChannel a) => 
      CredentialsProvider -- ^ A credentials provider to be used for 
                          -- authentication
   -> String -- ^ The name of the user to be authenticated
   -> String -- ^ The name of the service that you want to talk to
   -> StateT a IO (Maybe ByteString) -- ^ The communication to be run in a 
                                     -- channel, returning the shared master key
authenticate pdb username service = do
   mPassword <- lift $ (getPassword pdb) username service
   case mPassword of
      Nothing -> return Nothing
      Just passwd -> do let pwd = S.pack $ username <||> service <||> passwd
                        mSharedKey <- authenticate' username pwd service
                        when (isNothing mSharedKey) $ 
                           lift $ (failLogin pdb) username service
                        return $ mSharedKey

-- |Perform authentication without using a credentials provider. This is
-- normally not what you want to do!
authenticate' :: (CommunicationChannel a) => 
      String -- ^ The name of the user
   -> ByteString -- ^ The user's password
   -> String -- ^ The name of the service to talk to
   -> StateT a IO (Maybe ByteString) -- ^ The resulting communication, yielding 
                                     -- the master key
authenticate' myName' passwd hisName' = do
   -- myName == hisName is dangerous, because the attacker could now
   -- easily replay all knowledge proofs.
   if myName' == hisName'
      then lift $ return Nothing
      else do rng <- lift $ newGenIO :: StateT a IO HashDRBG
              -- Perform the actual JPAKE key exchange. First send our stage 1.
              let (secret', rng') = initializeSecret rng defaultGroup myName' 
                                                     hisName' 
              let secret = secret' {password = toLazy passwd}
              chanPutStrLn $ show $ buildJPAKEStage1 secret
              -- By now, the other peer should have sent their stage 1.
              msg1 <- chanGetLine
              lift $ logDebug $ "Got stage 1 from " ++ hisName' ++ ": " ++ msg1
              let hisStage1 = (read msg1) :: JPAKE ModPGroup
              -- Now send out stage 2. If we cannot build it, then something
              -- our peer sent was wrong. In that case, we should remember the 
              -- login failure.
              let ourStage2 = buildJPAKEStage2 secret hisStage1
              if isNothing ourStage2
                 then do lift $ logDebug "PEER'S STAGE 1 INVALID!"
                         return Nothing
                 else do 
                       lift $ logDebug "Sending out our stage 2"
                       chanPutStrLn $ show $ fromJust $ ourStage2
                       -- By now, our peer should also have sent their stage 2.
                       msg2 <- chanGetLine
                       lift $ logDebug $ "Got stage 2 from " ++ hisName' ++ ": " 
                                         ++ msg2
                       let hisStage2 = (read msg2) :: JPAKE ModPGroup
                       let dk = deriveKey secret hisStage1 hisStage2

                       -- Perform an explicit key confirmation step, to figure 
                       -- out if the peer knew the correct password or not.
                       confirmed <- maybe (return False) 
                                          ((fmap fst) . confirmKey defaultGroup 
                                                                   myName' 
                                                                   hisName' 
                                                                   rng' 
                                                      . toStrict) 
                                          dk
                       if (not confirmed)
                          then return Nothing
                          else return (toStrict `fmap` dk)
