{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
This module implements some convenience functions for using the secure channel
implementation. It is recommended to make use of these high-level functions, as
they (try to) take care of any step that is necessary for providing a
cryptographically secure communication channel.
-}

module Crypto.Protocol.SecureChannel.Simple (
   wrapChannelLocal, wrapChannelDelegate, setServiceData, 
   ServiceConfig(..), withAaaConnection, getServiceUsers, getServiceData
   )
where

import Network
import System.IO
import Crypto.Protocol.SecureChannel
import Crypto.Protocol.SecureChannel.KeyExchange
import Crypto.Util.CredentialsProvider
import Control.Monad.State
import Network.AAA.Protocol
import Data.Maybe

-- |Configuration data for a service.
data ServiceConfig = ServiceConfig {
      cServiceName  :: String -- ^ The name of the service
    , cAaaHost      :: String -- ^ The host name of the AAA service
    , cAaaPort      :: Int -- ^ The port number of the AAA service
    , cAaaName      :: String -- ^ The name of the AAA service
    , cCredProv     :: CredentialsProvider -- ^ A credentials provider for 
                                           -- providing the service password
   }

handshakeAAA :: (CommunicationChannel a) => 
    String 
 -> CredentialsProvider 
 -> String 
 -> StateT a IO (Maybe (RawChannel -> SecureChannel))
handshakeAAA myName pp aaaName = do
   sendCommand AuthServiceCommand
   chanPutStrLn myName
   mMasterKey <- authenticate pp myName aaaName
   case mMasterKey of
      Nothing -> return Nothing
      Just masterKey -> do let (skey, rkey) = deriveKeys masterKey myName 
                                                         aaaName
                           return $ Just $ buildSecureChannelAES skey rkey

-- Assumes we already have a communication channel with our client.
delegateAuthentication :: (CommunicationChannel a) => 
      String 
   -> Int 
   -> String 
   -> String 
   -> CredentialsProvider 
   -> StateT a IO (Maybe ((RawChannel -> SecureChannel), String, String))
delegateAuthentication delegateHost delegatePort aaaName myName pp = do
   delegateHandle <- lift $ connectTo delegateHost (PortNumber $ fromIntegral 
                                                                   delegatePort)
   lift $ hSetBuffering delegateHandle NoBuffering
   let delegateChan = handleToChannel delegateHandle 
   mSecBuilder <- lift $ evalChannel (handshakeAAA myName pp aaaName) 
                                     delegateChan
   case mSecBuilder of
      Nothing -> return Nothing
      Just f -> do let secAAAChan = f delegateChan
                   -- Get client's user name and stage1
                   clientUserName <- chanGetLine
                   clientStage1 <- chanGetLine
                   -- Send them over to the AAA server and
                   -- obtain the aaa server's stage 1 and 2
                   ((aaaStage1, aaaStage2), secAAAChan2) <- lift $ (flip runChannel) secAAAChan $ do
                       sendCommand AuthUserForServiceCommand
                       chanPutStrLn clientUserName
                       chanPutStrLn clientStage1
                       s1 <- chanGetLine
                       s2 <- chanGetLine
                       return (s1, s2)
                   -- Send aaa stages 1 and 2 to the client
                   chanPutStrLn aaaStage1
                   chanPutStrLn aaaStage2
                   -- Get client's stage 2
                   clientStage2 <- chanGetLine
                   -- And the client's key confirmation
                   clientConfirm <- chanGetLine
                   -- Send client's stage 2 and key confirmation to the aaa
                   -- and obtain the aaa key confirmation value
                   (aaaConfirm, secAAAChan3) <- lift $ (flip runChannel) secAAAChan2 $ do
                     chanPutStrLn clientStage2
                     chanPutStrLn clientConfirm
                     chanGetLine
                   -- Send the aaa key confirmation to the client
                   chanPutStrLn aaaConfirm
                   -- Now the aaa is supposed to send AuthSuccessCommand...
                   res <- lift $ (flip evalChannel) secAAAChan3 $ do
                             req <- chanGetLine
                             case (parseCommand req) of
                                Right (AuthSuccessCommand mk sd na) -> return $ Just (mk, sd, na)
                                _ -> return Nothing
                   case res of
                     Nothing -> return Nothing
                     Just (masterKey, serviceData, name) -> do let (sKey, rKey) = deriveKeys masterKey myName clientUserName
                                                               return $ Just $ (buildSecureChannelAES sKey rKey, serviceData, name)

sendCommand :: (CommunicationChannel a) =>
      Command 
   -> StateT a IO ()
sendCommand cmd = chanPutStrLn $ serialize cmd

readResponse :: (CommunicationChannel a) => StateT a IO (Maybe Command)
readResponse = do
   l <- chanGetLine
   case (parseCommand l) of
      Right cmd -> return $ Just cmd
      _         -> return Nothing

localAuthentication :: (CommunicationChannel a) => 
      String 
   -> CredentialsProvider 
   -> StateT a IO (Maybe (RawChannel -> SecureChannel))
localAuthentication serviceName pp = do
   myName <- lift $ (getUser pp) serviceName
   chanPutStrLn myName
   mSharedKey <- authenticate pp myName serviceName
   case mSharedKey of
      Nothing -> return Nothing
      Just sk -> do let (skey, rkey) = deriveKeys sk myName serviceName
                    return $ Just $ (buildSecureChannelAES skey rkey)

-- |Perform mutual authentication with a service and return a secure channel.
wrapChannelLocal :: RawChannel -- ^ The current (insecure) communication 
                               -- channel. May not be used afterwards!
                    -> String -- ^ The service name
                    -> CredentialsProvider -- ^ A credentials provider
                    -> IO (Maybe SecureChannel) -- ^ The secure channel (if 
                                                -- everything worked)
wrapChannelLocal chan service cp = do
   mFunc <- evalChannel (localAuthentication service cp) chan
   case mFunc of
      Nothing -> return Nothing
      Just f -> return $ Just $ f chan

-- |Perform mutual authentication with a client. This function is similar to
-- wrapChannelLocal, but it does not require the service to actually know the
-- password of the user who tries to connect. All authentication information
-- (i.e., the J-PAKE data) is forwarded to a so-called AAA service, which
-- authenticates the user and returns the master key back to the service.
wrapChannelDelegate :: RawChannel -- ^ The current (insecure) communication 
                                  -- channel. May not be used afterwards!
                       -> ServiceConfig -- ^ The service configuration
                       -> IO (Maybe (SecureChannel, String, String)) -- ^ A triple of: a secure channel, authorization information 
                                                                     -- (service data) and the name of the authenticated user.
wrapChannelDelegate chan cfg = do
   let aaaName = cAaaName cfg
   let aaaHost = cAaaHost cfg
   let aaaPort = cAaaPort cfg
   let cp      = cCredProv cfg
   myServiceName <- (getUser cp) aaaName
   mResult <- evalChannel (delegateAuthentication aaaHost aaaPort aaaName 
                                                  myServiceName cp) 
                          chan
   case mResult of
      Nothing -> return Nothing
      Just (f, sd, name) -> return $ Just $ (f chan, sd, name)

-- |Perform some channel communication inside a secure channel established with
-- an AAA server. This is useful mainly for implementing functionality like
-- password change inside a service.
withAaaConnection :: ServiceConfig -- ^ A service configuration
                     -> StateT SecureChannel IO a -- ^ The communication to run
                     -> IO (Maybe a) -- ^ The result of the communication (if 
                                     -- everything is OK)
withAaaConnection cfg chanAction = do
   aaaHandle <- connectTo (cAaaHost cfg) 
                          (PortNumber $ fromIntegral $ cAaaPort cfg)
   hSetBuffering aaaHandle NoBuffering
   let aaaChan = handleToChannel aaaHandle
   mSecBuilder <- evalChannel (handshakeAAA (cServiceName cfg) (cCredProv cfg) 
                                            (cAaaName cfg)) 
                              aaaChan
   case mSecBuilder of
      Nothing -> return Nothing
      Just f  -> do let secChan = f aaaChan
                    Just `fmap` evalChannel chanAction secChan

-- |Set the authorization information for a particular user.
setServiceData :: ServiceConfig -- ^ A service configuration
                  -> String -- ^ The user name
                  -> String -- ^ The authorization information
                  -> IO Bool -- ^ Did it work?
setServiceData cfg user sd = do
   res <- withAaaConnection cfg $ do
            sendCommand $ SetServiceDataCommand user sd
            resp <- readResponse
            case resp of
               Just AckCommand -> return True
               _               -> return False
   return $ fromMaybe False res

-- |Look up the authorization information of a particular user.
getServiceData :: ServiceConfig -- ^ A service configuration
                  -> String -- ^ The user name
                  -> IO (Maybe String) -- ^ The authorization data
getServiceData cfg user = do
   res <- withAaaConnection cfg $ do
            sendCommand $ GetServiceDataCommand user
            resp <- readResponse
            case resp of
               Just (ServiceDataCommand sd) -> return $ Just sd
               _                            -> return Nothing
   return $ fromMaybe Nothing res

-- |List the users that are allowd to use this service
getServiceUsers :: ServiceConfig -- ^ A service configuration
                   -> IO [String] -- ^ The list of user names (potentially 
                                  -- empty)
getServiceUsers cfg = do
   res <- withAaaConnection cfg $ do
            sendCommand $ ListUsersCommand
            resp <- readResponse
            case resp of
               Just (AccountNamesCommand l) -> return l
               _                            -> return []
   return $ fromMaybe [] res
