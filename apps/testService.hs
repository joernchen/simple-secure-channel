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

mkConfig cp = ServiceConfig {
   cAaaName = "AAA Service",
   cAaaHost = "127.0.0.1",
   cAaaPort = 1234,
   cServiceName = "testService",
   cCredProv = cp
   }

askUser _     = return "testService"
askPass _ _   = return "test"
askUseOtp _ _ = return False
askOtp _ _    = return ""

handler cfg tcpConn = do
   let plainChan = handleToChannel $ connHandle tcpConn
   result <- wrapChannelDelegate plainChan cfg
   case result of
      Nothing -> return ()
      Just (secChan, _, user) -> do evalChannel (chanPutStrLn $ "Hello, " ++ user) secChan
                                    return ()

main = do
   pp <- genCredentialsProvider askUser askPass askUseOtp askOtp
   let cfg = mkConfig pp
   forkingTcpServer "0.0.0.0" 1337 (handler cfg)
