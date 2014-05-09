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
import Network.AAA.Protocol
import Crypto.Util.CredentialsProvider hiding (getUser)
import Network
import Control.Monad
import Control.Monad.State
import System.IO
import System.Environment
import System.Console.GetOpt
import Data.Maybe

askUseOtp :: String -> String -> IO Bool
askUseOtp user service = do
   putStr $ "Do you need to use OTP for logging in as " ++ user ++ " on " ++  
            service ++ "? (Y/N): "
   hFlush stdout
   yn <- getLine
   if yn == "Y"
      then return True
      else if yn == "N"
            then return False
            else askUseOtp user service

askOtp :: String -> String -> IO String
askOtp user service = do
   putStr $ "Enter OTP secret for " ++ user ++ " on " ++ service ++ ": "
   hFlush stdout
   doAskPass

askPass :: String -> String -> IO String
askPass user service = do 
   putStr $ "Enter password for " ++ user ++ " on " ++ service ++ ": "
   hFlush stdout
   doAskPass

askPassTwice :: String -> IO String
askPassTwice user = do
   putStr $ "Enter new password for " ++ user ++ ": "
   hFlush stdout
   pwd1 <- doAskPass
   putStr $ "Again: "
   hFlush stdout
   pwd2 <- doAskPass
   if (pwd1 == pwd2)
      then return pwd1
      else putStrLn "Passwords did not match. Once again." >> askPassTwice user

askOtpTwice :: String -> IO String
askOtpTwice user = do
   putStr $ "Enter new OTP secret for " ++ user ++ ": "
   hFlush stdout
   pwd1 <- doAskPass
   putStr $ "Again: "
   hFlush stdout
   pwd2 <- doAskPass
   if (pwd1 == pwd2)
      then return pwd1
      else putStrLn "Secrets did not match. Once again." >> askOtpTwice user

doAskPass :: IO String
doAskPass = do
   e <- hGetEcho stdin
   hFlush stdout
   hSetEcho stdin False
   pwd <- getLine
   hSetEcho stdin e
   putStrLn ""
   return pwd

sendCommand :: (CommunicationChannel a) => Command -> StateT a IO ()
sendCommand cmd = do
   chanPutStrLn $ serialize cmd

receiveResponse = do
   line <- chanGetLine
   return $ parseCommand line

sendReceive cmd = sendCommand cmd >> receiveResponse

isAck (Right AckCommand) = True
isAck _ = False

extractList (Right (AccountNamesCommand lst)) = lst
extractList _ = []

runCmdBool :: Command -> StateT SecureChannel IO Bool
runCmdBool cmd = do
   resp <- sendReceive cmd
   return $ isAck resp

changePassword :: String -> StateT SecureChannel IO Bool
changePassword = runCmdBool . ChangePasswordCommand

changePassword' :: String -> String -> StateT SecureChannel IO Bool
changePassword' u pw = runCmdBool $ SetPasswordCommand u pw

addUser :: String -> String -> StateT SecureChannel IO Bool
addUser u pw = runCmdBool $ AddUserCommand u pw

addService :: String -> String -> StateT SecureChannel IO Bool
addService s pw = runCmdBool $ AddServiceCommand s pw

addServiceSecure :: String -> StateT SecureChannel IO ()
addServiceSecure s = do
   res <- sendReceive $ AddServiceSecureCommand s
   case res of
      Right (ServicePasswordIsCommand pw) -> lift $ putStrLn $ "Password is " 
                                                               ++ pw
      _ -> lift $ putStrLn "Nope, sorry."

setOtp :: String -> StateT SecureChannel IO Bool
setOtp secret = runCmdBool $ SetOTPSecretCommand secret

setUserOtp :: String -> String -> StateT SecureChannel IO Bool
setUserOtp u s = runCmdBool $ SetUserOTPSecretCommand u s

disableOtp :: StateT SecureChannel IO Bool
disableOtp = runCmdBool $ DisableOTPCommand

disableUserOtp :: String -> StateT SecureChannel IO Bool
disableUserOtp u = runCmdBool $ DisableUserOTPCommand u

delUser :: String -> StateT SecureChannel IO Bool
delUser user = runCmdBool $ DelUserCommand user

delService :: String -> StateT SecureChannel IO Bool
delService name = runCmdBool $ DelServiceCommand name

allowUserForService :: String -> String -> StateT SecureChannel IO Bool
allowUserForService user service = runCmdBool $ AllowCommand user service

denyUserForService :: String -> String -> StateT SecureChannel IO Bool
denyUserForService user service = runCmdBool $ DenyCommand user service

listUsers :: StateT SecureChannel IO [String]
listUsers = do
   resp <- sendReceive $ ListUsersCommand
   return $ extractList resp

listServices :: StateT SecureChannel IO [String]
listServices = do
   resp <- sendReceive $ ListServicesCommand
   return $ extractList resp

listUsersForService :: String -> StateT SecureChannel IO [String]
listUsersForService service = do
   resp <- sendReceive $ UsersForServiceCommand service
   return $ extractList resp

listServicesForUser :: String -> StateT SecureChannel IO [String]
listServicesForUser user = do
   resp <- sendReceive $ ServicesForUserCommand user
   return $ extractList resp

printResult :: IO Bool -> IO ()
printResult action = do
   res <- action
   if res
      then putStrLn "OK"
      else putStrLn "Nope, sorry."

serveRequests :: Options -> SecureChannel -> IO ()
serveRequests opts chan = do
   let cmd     = getAction opts
   let user    = getUser opts
   let service = getService opts
   let login'  = login opts
   case cmd of
      Adduser   -> do pass <- askPassTwice user
                      printResult $ evalChannel (addUser user pass) chan
      Deluser   -> printResult $ evalChannel (delUser user) chan
      Addservice   -> do pass <- askPassTwice (getService opts)
                         printResult $ evalChannel (addService service pass) 
                                                   chan
      Addsecservice -> evalChannel (addServiceSecure service) chan
      Delservice   -> printResult $ evalChannel (delService service) chan
      Passwd    -> do pass <- askPassTwice login'
                      printResult $ evalChannel (changePassword pass) chan
      Listusers -> evalChannel listUsers chan >>= mapM_ putStrLn
      Listservices -> evalChannel listServices chan >>= mapM_ putStrLn
      Usersforservice -> evalChannel (listUsersForService service) chan 
                         >>= mapM_ putStrLn
      Servicesforuser -> evalChannel (listServicesForUser user) chan 
                         >>= mapM_ putStrLn
      Allowforservice -> printResult $ evalChannel (allowUserForService user
                                                              service) 
                                      chan
      Denyforservice -> printResult $ evalChannel (denyUserForService user
                                                           service) 
                                      chan
      Changepassword -> do pass <- askPassTwice user
                           printResult $ evalChannel (changePassword' user
                                                           pass) 
                                         chan
      Setotp         -> do secret <- askOtpTwice login'
                           printResult $ evalChannel (setOtp secret) chan
      Setuserotp     -> do secret <- askOtpTwice user
                           printResult $ evalChannel (setUserOtp user 
                                                                 secret) chan
      Disableotp     -> do printResult $ evalChannel disableOtp chan
      Disableuserotp -> do printResult $ evalChannel (disableUserOtp user) chan

data Action =   Adduser | Deluser | Addservice | Addsecservice | Delservice
              | Passwd | Listusers
              | Listservices | Usersforservice | Servicesforuser 
              | Allowforservice | Denyforservice
              | Changepassword | Setotp | Setuserotp | Disableotp 
              | Disableuserotp
              deriving (Show)

data Options = Options {
     action      :: Maybe Action
   , username    :: Maybe String
   , login       :: String
   , servicename :: Maybe String
   , server      :: Maybe String
   , port        :: Int
   , aaaName     :: String
   } deriving (Show)

defaultOptions :: Options
defaultOptions = Options {
     action      = Nothing
   , username    = Nothing
   , login       = "admin"
   , servicename = Nothing
   , port        = 1234
   , server      = Nothing
   , aaaName     = "AAA Service"
   }

actions :: [(String, Action)]
actions = [
     ("adduser", Adduser)
   , ("deluser", Deluser)
   , ("addservice", Addservice)
   , ("addsecservice", Addsecservice)
   , ("delservice", Delservice)
   , ("passwd", Passwd)
   , ("listusers", Listusers)
   , ("listservices", Listservices)
   , ("usersforservice", Usersforservice)
   , ("servicesforuser", Servicesforuser)
   , ("allowforservice", Allowforservice)
   , ("denyforservice", Denyforservice)
   , ("chpass", Changepassword)
   , ("setotp", Setotp)
   , ("setuserotp", Setuserotp)
   , ("disableotp", Disableotp)
   , ("disableuserotp", Disableuserotp)
   ]

parseAction :: String -> Maybe Action
parseAction = (flip lookup) actions

options :: [OptDescr (Options -> Options)]
options = [
     Option ['a'] ["action"]  (ReqArg (\s opts -> opts { action = parseAction s }) "ACTION") $ "action to perform; one of " ++ 
                                                                                             (show $ map fst actions)
   , Option ['u'] ["user"]    (ReqArg (\s opts -> opts { username = Just s }) "USER") "Name of user to work on"
   , Option ['s'] ["service"] (ReqArg (\s opts -> opts { servicename = Just s }) "SERVICE") "Name of service to work on"
   , Option ['l'] ["login"]   (ReqArg (\s opts -> opts { login = s }) "USER") "Your user name for the AAA service"
   , Option ['h'] ["host"]    (ReqArg (\s opts -> opts { server = Just s }) "HOST") "Host name of the AAA service"
   , Option ['p'] ["port"]    (ReqArg (\s opts -> opts { port = read s }) "PORT") "Port number of the AAA service"
   , Option ['n'] ["aaaName"] (ReqArg (\s opts -> opts { aaaName = s }) "NAME") "Name of the AAA Service"
   ]

tryOption :: (Options -> Maybe a) -> String -> Options -> a
tryOption func errMsg opts = fromMaybe (error errMsg) (func opts)

getAction :: Options -> Action
getAction = tryOption action "No action specified. Try --help."

getUser :: Options -> String
getUser = tryOption username "The specified action requires a user name to be\
                             \supplied."

getService :: Options -> String
getService = tryOption servicename "The specified action requires a service\
                                   \name to be supplied."

getServer :: Options -> String
getServer = tryOption server "You need to supply the host name of the AAA\
                             \service. Try --help."

getOptions :: [String] -> IO Options
getOptions args =
   case getOpt Permute options args of
      (o,[],[])    -> return $ Prelude.foldl (flip id) defaultOptions o
      (_,(u:us),_) -> ioError $ userError $ "Unknown option detected.\n" ++ 
                                            usageInfo header options
      (_,[],errs)  -> ioError $ userError $ Prelude.concat errs ++ 
                                            usageInfo header options
   where header = "Usage:"

main = do
   opts <- getArgs >>= getOptions
   hSetBuffering stdin NoBuffering
   pp <- genCredentialsProvider (\_ -> return (login opts)) askPass askUseOtp 
                                askOtp
   plainHandle <- connectTo (getServer opts) 
                            (PortNumber $ fromIntegral (port opts))
   let plainChan = handleToChannel plainHandle
   evalChannel (sendCommand AuthUserCommand) plainChan
   secChan <- wrapChannelLocal plainChan (aaaName opts) pp
   case secChan of
      Nothing -> return ()
      Just chan -> do serveRequests opts chan
                      return ()
