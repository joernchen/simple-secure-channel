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
import Network
import Control.Monad
import Control.Monad.State
import System.IO
import qualified Data.ByteString as BS
import Control.Concurrent
import Data.Time.Clock
import Crypto.Util.Encoding

-- Static values - most simple case
askUser _     = return "userName"
askPass _ _   = return "userPass"
-- askUseOtp _ _ = return $ askUseOtp askUser "testService" 
askUseOtp _ _ = do
   putStr $ "Do you need to use OTP for logging in? (Y/N): "
   hFlush stdout
   yn <- getLine
   if yn == "Y"
      then return True
      else if yn == "N"
            then return False
            else askUseOtp "" ""

askOtp _ _ = do
   putStr $ "Enter OTP: "
   hFlush stdout
   doAskPass

doAskPass :: IO String
doAskPass = do
   e <- hGetEcho stdin
   hFlush stdout
   --hSetEcho stdin False
   pwd <- getLine
   --hSetEcho stdin e
   putStrLn ""
   return pwd



data Direction = Encrypt | Decrypt

proxy :: Handle -> Direction -> StateT SecureChannel IO ()
proxy h Decrypt = forever $ do
   plain <- recvSome 1024
   lift $ BS.hPut h plain
proxy h Encrypt = forever $ do
   plain <- lift $ BS.hGetSome h 1024
   if BS.length plain == 0
      then error "Socket closed."
      else send plain

main = do
   hSetBuffering stdin NoBuffering
   pp <- genCredentialsProvider askUser askPass askUseOtp askOtp
   plainHandle <- connectTo "127.0.0.1" (PortNumber $ fromIntegral 1337)
   secChan <- wrapChannelLocal (handleToChannel plainHandle) "testService" pp
   case secChan of
      Nothing -> return ()
      Just chan -> do forkIO $ evalChannel (proxy stdin Encrypt) chan
                      evalChannel (proxy stdout Decrypt) chan
                      return ()
