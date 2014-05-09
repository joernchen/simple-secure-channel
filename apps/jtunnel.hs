{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

import Crypto.Protocol.SecureChannel
import Crypto.Protocol.SecureChannel.Simple
import Crypto.Util.CredentialsProvider
import Network.TCPServer
import Network
import System.IO
import Control.Concurrent
import Data.Maybe
import Data.IP
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Control.Monad
import Control.Monad.State
import Text.Read (readMaybe)
import System.IO.Temp
import System.Process
import System.Environment
import Text.Show.Pretty
import Network.DNS.Lookup
import Network.DNS.Resolver

data Direction = Encrypt | Decrypt

data HostSpec = HostName String
              | Range (AddrRange IPv4)
              deriving (Show, Read)

data TunnelPermission = TunnelPermission {
      allow :: Bool,
      host  :: HostSpec,
      ports :: (Int, Int)
   } deriving (Show, Read)

defaultPermissions :: [TunnelPermission]
defaultPermissions = [TunnelPermission {
      allow = True,
      host  = Range $ (read "0.0.0.0/0"),
      ports = (0,65535)
   }]

askUser _     = return "testService"
askPass _ _   = return "test"
askUseOtp _ _ = return False
askOtp _ _    = return ""

mkConfig cp = ServiceConfig {
   cAaaName = "AAA Service",
   cAaaHost = "127.0.0.1",
   cAaaPort = 1234,
   cServiceName = "testService",
   cCredProv = cp
   }

proxy :: Handle -> Direction -> StateT SecureChannel IO ()
proxy h Decrypt = forever $ do
   plain <- recvSome 1024
   lift $ BS.hPut h plain
proxy h Encrypt = forever $ do
   plain <- lift $ BS.hGetSome h 1024
   if BS.length plain == 0
      then error "Socket closed."
      else send plain

parsePermissions :: String -> [TunnelPermission]
parsePermissions str =
   case readMaybe str of
      Nothing -> defaultPermissions
      Just perms -> perms

handler cfg tcpConn = do
   let plainChan = handleToChannel $ connHandle tcpConn
   result <- wrapChannelDelegate plainChan cfg
   case result of
      Nothing -> return () 
      Just (secChan, perms, user) -> do evalChannel (processRequest (parsePermissions perms)) secChan
                                        return ()

myLookup :: String -> IO [IPv4]
myLookup h = do
   rs <- makeResolvSeed defaultResolvConf
   result <- withResolver rs $ \r -> lookupA r (C8.pack h)
   return $ case result of
      Left  _ -> []
      Right x -> x

processRequest :: [TunnelPermission] -> StateT SecureChannel IO ()
processRequest perms = do
   host <- chanGetLine
   port <- read `fmap` chanGetLine
   lift $ putStrLn $ "Got host " ++ host ++ " and port " ++ (show port)
   addrs <- lift $ myLookup host
   if (checkPermission perms host addrs port)
      then do plainHandle <- lift $ connectTo host (PortNumber $ fromIntegral port)
              lift $ hSetBuffering plainHandle NoBuffering
              lift $ putStrLn "Connection to remote service established. Will now proxy."
              -- XXX FIXME Ugly hack
              chan <- get
              lift $ forkIO $ evalChannel (proxy plainHandle Encrypt) chan
              proxy plainHandle Decrypt
      else do lift $ putStrLn "Insufficient permissions, sorry."
              return ()

checkPermission :: [TunnelPermission] -> String -> [IPv4] -> Int -> Bool
checkPermission perms host addrs port =
   head $ (mapMaybe (checkOnePermission host addrs port) perms) ++ [False]

checkOnePermission :: String -> [IPv4] -> Int -> TunnelPermission -> Maybe Bool
checkOnePermission hostName addrs port perm = 
   let (startPort, endPort) = ports perm
       portMatch = (port >= startPort) && (port <= endPort)
       ips = let hip = readMaybe hostName
             in case hip of
               Nothing -> addrs
               Just ip -> [ip]
   in
   case (host perm) of
      HostName name -> if (name == hostName) && portMatch
                          then Just (allow perm)
                          else Nothing
      Range range   -> if True `elem` map ((flip isMatchedTo) range) ips && portMatch
                          then Just (allow perm)
                          else Nothing

editServiceData :: ServiceConfig -> String -> IO ()
editServiceData cfg user = do
   mSd    <- getServiceData cfg user
   case mSd of
      Nothing -> putStrLn "Cannot get service data. Invalid user?"
      Just sd -> do let perms = fromMaybe defaultPermissions (readMaybe sd)
                    sdNew <- withSystemTempFile "jtunnelpermissionsXXXXXX" $ \fp h -> do
                       hPutStrLn h (ppShow perms)
                       hClose h
                       system $ "${EDITOR:-vi} " ++ fp
                       readFile fp
                    let mPermsNew = readMaybe sdNew :: Maybe [TunnelPermission]
                    case mPermsNew of
                       Nothing -> putStrLn "Cannot parse."
                       Just newPerms -> do res <- setServiceData cfg user (show newPerms)
                                           if res
                                             then putStrLn "OK"
                                             else putStrLn "Nope, sorry."

main = do
   args <- getArgs
   pp <- genCredentialsProvider askUser askPass askUseOtp askOtp
   let cfg = mkConfig pp

   if length args > 0
      then case (head args) of
         "edit" -> editServiceData cfg (head $ tail args)
         "list" -> do users <- getServiceUsers cfg
                      mapM_ putStrLn users
      else do forkingTcpServer "0.0.0.0" 1337 (handler cfg)
