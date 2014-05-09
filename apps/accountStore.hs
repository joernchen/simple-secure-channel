{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

import Control.Monad (when, forever)
import Database.HDBC
import Database.HDBC.Sqlite3
import Data.Time.Clock.POSIX
import Crypto.Protocol.SecureChannel
import Crypto.Protocol.SecureChannel.KeyExchange
import Crypto.Util.Encoding
import System.Directory
import Control.Monad.State
import Data.ByteString hiding (length, map, tail, head, putStrLn, replicate)
import qualified Data.ByteString.Char8 as C8
import qualified Network.TCPServer as TCP
import System.Log.Logger
import Network.AAA.Protocol
import Data.Maybe
import Crypto.Random
import Crypto.Random.DRBG
import Codec.Binary.Base64.String
import System.Console.GetOpt
import System.FilePath
import System.Environment
import Data.OTP
import Data.Time.Clock
import Data.Word

data PasswordResult = Unknown | Blocked | Password String

logWarning = warningM "accountStore"
logDebug   = debugM   "accountStore"
logError   = errorM   "accountStore"
logInfo    = infoM    "accountStore"

getTime :: IO Integer
getTime = do
   x <- getPOSIXTime
   return $ round x

setupDatabase :: Connection -> IO ()
setupDatabase conn = do
   run conn "CREATE TABLE users (name TEXT, password TEXT, \
                                 \otpSecret TEXT default NULL, \
                                 \failed INTEGER default 0, \
                                 \lastFail INTEGER, PRIMARY KEY(name))" 
       []
   run conn "CREATE TABLE services (name TEXT, password TEXT, \
                                   \secureService INTEGER default 0, \
                                   \otpSecret TEXT default NULL, \
                                   \failed INTEGER default 0, \
                                   \lastFail INTEGER, PRIMARY KEY(name))" 
       []
   run conn "CREATE TABLE users_services (user INTEGER NOT NULL, \
                                         \service INTEGER NOT NULL, \
                                         \servicedata TEXT DEFAULT '')" 
       []
   commit conn

isAdmin :: Connection -> String -> IO Bool
isAdmin conn user = do
   ourName  <- getOurName
   (res, _) <- getUserPasswordAndServiceData conn user ourName
   case res of
      Password _ -> return True
      _          -> return False

setServiceData :: Connection -> String -> String -> String -> IO Bool
setServiceData conn serviceName user sd = do
   cnt <- run conn "UPDATE users_services SET servicedata = ? \
                   \WHERE user = (SELECT rowid FROM users WHERE name=?) \
                   \AND service = (SELECT rowid FROM services WHERE name = ?)" 
              [toSql sd, toSql user, toSql serviceName]
   return (cnt == 1)

getServiceData :: Connection -> String -> String -> IO String
getServiceData conn service user = do
   rows <- quickQuery' conn "SELECT users_services.servicedata \
                            \FROM users_services, users, services \
                            \WHERE users.rowid = users_services.user \
                            \AND users.name = ? \
                            \AND users_services.service = services.rowid \
                            \AND services.name = ?"
                       [toSql user, toSql service]
   if length rows == 0
      then return ""
      else return $ fromSql ((head rows) !! 0)

changeUserPassword :: Connection -> String -> String -> IO Bool
changeUserPassword conn user pw = do
   cnt <- run conn "UPDATE users SET password = ?, failed = 0 WHERE name = ?" 
              [toSql pw, toSql user]
   return (cnt == 1)

changeServicePassword :: Connection -> String -> String -> IO Bool
changeServicePassword conn service pw = do
   rows <- run conn "UPDATE services SET password = ? WHERE name = ? \
                    \AND secureService = 0" 
               [toSql pw, toSql service]
   return (rows > 0)

listUsers :: Connection -> IO [String]
listUsers conn = do
   rows <- quickQuery' conn "SELECT name FROM users" []
   return $ map (fromSql . head) rows

listServices :: Connection -> IO [String]
listServices conn = do
   rows <- quickQuery' conn "SELECT name FROM services" []
   return $ map (fromSql . head) rows

listServicesForUser :: Connection -> String -> IO [String]
listServicesForUser conn name = do
   rows <- quickQuery' conn "SELECT services.name FROM services, users, \
                                                      \users_services \
                            \WHERE users.rowid = users_services.user \
                            \AND users.name = ? \
                            \AND users_services.service = services.rowid" 
                       [toSql name]
   return $ map (fromSql . head) rows

listUsersForService :: Connection -> String -> IO [String]
listUsersForService conn name = do
   rows <- quickQuery' conn "SELECT users.name FROM services, users, \
                                                    \users_services \
                            \WHERE services.rowid = users_services.service \
                            \AND services.name = ? \
                            \AND users_services.user = users.rowid" 
                       [toSql name]
   return $ map (fromSql . head) rows

allowUserForService :: Connection -> String -> String -> IO Bool
allowUserForService conn user service = do
  (res, _) <- getUserPasswordAndServiceData conn user service
  case res of
     Password _ -> return True
     Blocked    -> return True
     Unknown -> do rows <- quickQuery' conn "SELECT users.rowid, services.rowid\
                                            \ FROM users, services\
                                            \ WHERE users.name = ?\
                                            \ AND services.name = ?" 
                                       [toSql user, toSql service]
                   if (length rows /= 1)
                     then return False
                     else do run conn "INSERT INTO users_services(user,service)\
                                      \ VALUES(?,?)" 
                                 (head rows)
                             return True

denyUserForService :: Connection -> String -> String -> IO Bool
denyUserForService conn user service = do
  (res, _) <- getUserPasswordAndServiceData conn user service
  case res of
     Unknown -> return True
     _       -> do rows <- quickQuery' conn "SELECT users.rowid, services.rowid\
                                            \ FROM users, servicse\
                                            \ WHERE users.name = ?\
                                            \ AND services.name = ?" 
                                       [toSql user, toSql service]
                   if (length rows /= 1)
                     then return True
                     else do run conn "DELETE FROM users_services\
                                      \ WHERE user = ? AND service = ?" 
                                 (head rows)
                             return True

addUser :: Connection -> String -> String -> IO Bool
addUser conn user password = do
   rows <- quickQuery' conn "SELECT * FROM users WHERE name = ?" [toSql user]
   case length rows of
      0 -> do run conn "INSERT into users(name,password) values(?, ?)"
                  [toSql user, toSql password]
              return True
      _ -> return False

addService' :: Connection -> String -> String -> Bool -> IO Bool
addService' conn name password sec = do
   let ss = if sec then 1 else 0 :: Int
   rows <- quickQuery' conn "SELECT * FROM services WHERE name = ?" [toSql name]
   case length rows of
      0 -> do run conn "INSERT into services(name,password,secureService)\
                       \ VALUES(?, ?, ?)" 
                  [toSql name, toSql password, toSql ss]
              return True
      _ -> return False

addService :: Connection -> String -> String -> IO Bool
addService conn name password = addService' conn name password False

addServiceSecure :: Connection -> String -> IO (Maybe String)
addServiceSecure conn user = do
   g <- newGenIO :: IO HashDRBG
   let Right (v, _) = genBytes 16 g
   let password = encode $ C8.unpack v
   res <- addService' conn user password True
   if res
      then return $ Just password
      else return Nothing

deleteUser :: Connection -> String -> IO Bool
deleteUser conn user = do
   cnt <- run conn "DELETE FROM users, users_services WHERE users.name = ?\
                   \ AND users_services.user = users.rowid" 
              [toSql user]
   return (cnt == 1)

deleteService :: Connection -> String -> IO Bool
deleteService conn name = do
   cnt <- run conn "DELETE FROM services, users_services\
                   \ WHERE services.name = ?\
                   \ AND users_services.service = services.rowid" 
              [toSql name]
   return (cnt == 1)

initialSetup :: Connection -> IO ()
initialSetup conn = do
   setupDatabase conn
   gen <- newGenIO :: IO HashDRBG
   let Right (v, _) = genBytes 8 gen
   let password = encode $ C8.unpack v
   addUser conn "admin" password
   ourName <- getOurName
   addService conn ourName password
   allowUserForService conn "admin" ourName
   commit conn
   putStrLn $ "This is the first time you run this server. Admin credentials\
              \are: admin / " ++ password

openDatabase :: String -> IO Connection
openDatabase fileName = do
   logDebug $ "Opening database file " ++ fileName
   e <- doesFileExist fileName
   conn <- connectSqlite3 fileName
   when (not e) (initialSetup conn)
   logDebug $ "Database opened."
   return conn

getPassword' :: Connection -> String -> String -> IO PasswordResult
getPassword' conn table name = do
   let svc = table == "services"
   let q = if svc 
               then quickQuery' conn ("SELECT password, failed, lastFail,\
                                      \ secureService FROM services\
                                      \ WHERE name = ?") 
                                [toSql name]
               else quickQuery' conn ("SELECT password, failed, lastFail\
                                      \ FROM users WHERE name = ?") 
                                [toSql name]
   logDebug $ "Looking up password for " ++ name
   rows <- q
   let pwd = fromSql $ head $ head $ rows
   case (length rows) of
      0 -> do logDebug "No such account."
              return Unknown
      _ -> do
             otp <- getOTP' conn table name
             let (failed:lastFail:rest) = map fromSql $
                                              tail (rows !! 0) :: [Integer]
             let delta = 4 * (2^failed)
             curTime <- getTime
             if failed == 0 || curTime > lastFail + delta
               then do logDebug "Password lookup succeeded."
                       case otp of
                          Nothing -> return $ Password pwd
                          Just i  -> do let j = show i
                                        let k = 6 - (length j)
                                        let o = replicate k '0' ++ j
                                        return $ Password $ pwd <||> o
               else do if svc && (head rest) == 1
                          then do logDebug "Block ignored for secure service."
                                  return $ Password pwd
                          else do logDebug $ "User is blocked until " ++ 
                                             show(lastFail + delta) ++ "."
                                  return $ Blocked

setOTP' :: Connection -> String -> String -> IO Bool
setOTP' conn user secret = do
   cnt <- run conn "UPDATE users SET otpSecret=? WHERE name=?" 
              [toSql secret, toSql user]
   return (cnt == 1)

disableOTP' :: Connection -> String -> IO Bool
disableOTP' conn user = do
   cnt <- run conn "UPDATE users SET otpSecret=null WHERE name=?" [toSql user]
   return (cnt == 1)

getOTP' :: Connection -> String -> String -> IO (Maybe Int)
getOTP' conn table name = do rows <- quickQuery' conn ("SELECT otpSecret FROM "
                                                       ++ table ++ 
                                                       " WHERE name = ?") 
                                                 [toSql name]
                             let otp = fromSql ((rows !! 0) !! 0)
                             case otp of 
                                SqlNull -> return $ Nothing
                                _       -> do t <- getCurrentTime
                                              let p = totp (unpack $ 
                                                                fromSql otp) 
                                                           t 6 30 
                                              return $ Just p 

succeedLogin' :: Connection -> String -> String -> IO ()
succeedLogin' conn table name = do
   run conn ("UPDATE " ++ table ++ " SET failed = 0, lastFail = 0 WHERE\
             \ name = ?") 
       [toSql name]
   commit conn
   logDebug $ "Login for account " ++ name ++ " succeeded."

failLogin' :: Connection -> String -> String -> IO ()
failLogin' conn table name = do
   run conn ("UPDATE " ++ table ++ " SET failed = failed + 1, \
             \lastFail = strftime('%s','now') WHERE name = ?") 
       [toSql name]
   return ()
   logDebug $ "Login for account " ++ name ++ " failed."

getUserPasswordAndServiceData ::    Connection 
                                 -> String 
                                 -> String 
                                 -> IO (PasswordResult, String)
getUserPasswordAndServiceData conn user service = do
   rows <- quickQuery' conn "SELECT servicedata FROM users_services, users, \
                                                    \services \
                            \WHERE services.rowid = users_services.service \
                            \AND users.rowid = users_services.user \
                            \AND users.name = ? AND services.name = ?" 
                       [toSql user, toSql service]
   case rows of
      (row:[]) -> do
                     logDebug $ "Successfully found user " ++ user ++ 
                                " for service " ++ service
                     pwd <- getPassword' conn "users" user
                     return (pwd, fromSql (row !! 0))
      _ -> do logDebug $ "User " ++ user ++ " is not allowed to use service " 
                         ++ service ++ 
                         " (potentially the user is not even present)."
              return (Unknown, "")
      

getOurName :: IO String
getOurName = return "AAA Service"

-- This will read the peer name from the channel
handshakeWithService ::
           Connection 
        -> StateT RawChannel IO (Maybe ((RawChannel -> SecureChannel), String))
handshakeWithService conn = do
   ourName   <- lift getOurName
   theirName <- chanGetLine
   lift $ logInfo $ "Handshaking with service " ++ theirName
   pwd       <- lift $ getPassword' conn "services" theirName
   case pwd of
      Unknown -> return Nothing
      Blocked -> return Nothing
      Password password -> do let pwd' = C8.pack $ theirName <||> ourName <||>
                                                   password
                              mMasterKey <- authenticate' ourName pwd' theirName
                              case mMasterKey of
                                 Nothing -> do lift $ failLogin' conn "services"
                                                                 theirName
                                               return $ Nothing
                                 Just masterKey -> do lift $ succeedLogin' conn
                                                                "services" 
                                                                theirName
                                                      let (skey, rkey) = deriveKeys masterKey ourName theirName
                                                      return $ Just $ (buildSecureChannelAES skey rkey, theirName)

handshakeWithUser :: (CommunicationChannel a) => 
      Connection 
   -> Maybe String 
   -> StateT a IO (Maybe (ByteString, String, String))
handshakeWithUser conn mServiceName = do
   theirName <- chanGetLine
   ourName <- lift $ getOurName
   let serviceName = fromMaybe ourName mServiceName
   lift $ logInfo $ "Authenticating user " ++ theirName
   (pwd, serviceData) <- case mServiceName of
      Nothing -> do pwd <- lift $ getPassword' conn "users" theirName
                    return (pwd, "")
      Just sn -> lift $ getUserPasswordAndServiceData conn theirName sn
   case pwd of
      Unknown -> return Nothing
      Blocked -> return Nothing
      Password pw -> do let pwd' = C8.pack $ theirName <||> serviceName <||> pw
                        mMasterKey <- authenticate' serviceName pwd' theirName
                        case mMasterKey of
                           Nothing -> do lift $ failLogin' conn "users" 
                                                           theirName
                                         return Nothing
                           Just masterKey -> do lift $ succeedLogin' conn 
                                                                     "users" 
                                                                     theirName
                                                return $ Just $ (masterKey, 
                                                                 serviceData, 
                                                                 theirName)

shareMasterKey :: (CommunicationChannel a) => 
      ByteString 
   -> String 
   -> String 
   -> StateT a IO ()
shareMasterKey masterKey sd name = do
   sendCommand (AuthSuccessCommand masterKey sd name)
   lift $ logDebug $ "Sent the master key to the service."

handleNetworkConnection :: RawChannel -> Connection -> IO ()
handleNetworkConnection chan conn = do
   mResult <- evalChannel (doAuthentication conn) chan
   case mResult of
      Nothing    -> do logWarning "Authentication failed."
                       return ()
      Just (f,name,isUser) -> do let secChan = f chan
                                 logDebug $ "Authentication OK. Account = " 
                                            ++ name ++ " isUser = " 
                                            ++ show(isUser)
                                 if isUser
                                   then evalChannel (serveUserRequests conn 
                                                                       name)
                                                    secChan
                                   else evalChannel (serveServiceRequests conn 
                                                                          name) 
                                                    secChan

doAuthentication ::
      Connection 
   -> StateT RawChannel IO (Maybe ((RawChannel -> SecureChannel), String, Bool))
doAuthentication conn = do
   request <- chanGetLine
   ourName <- lift $ getOurName
   case (parseCommand request) of
      Right AuthUserCommand    -> do lift $ logDebug "Authenticate user request"
                                     mResult <- handshakeWithUser conn Nothing
                                     case mResult of
                                       Nothing -> return Nothing
                                       Just (masterKey, _, name) -> do let (skey, rkey) = deriveKeys masterKey ourName name
                                                                       let f = buildSecureChannelAES skey rkey
                                                                       return $ Just (f, name, True)
      Right AuthServiceCommand -> do lift $ logDebug "Authenticate service request"
                                     mResult <- handshakeWithService conn
                                     case mResult of
                                       Nothing         -> return Nothing
                                       Just (f, name)  -> return $ Just (f, name, False)
      _          -> do lift $ logInfo $ "Received garbage request: " ++ request
                       return Nothing
      

sendCommand :: (CommunicationChannel a) => Command -> StateT a IO ()
sendCommand cmd = do
   chanPutStrLn $ serialize cmd

serveServiceRequests :: Connection -> String -> StateT SecureChannel IO ()
serveServiceRequests conn serviceName = forever $ do
   request <- chanGetLine
   case (parseCommand request) of
      Right AuthUserForServiceCommand -> do mResult <- handshakeWithUser conn (Just serviceName)
                                            case mResult of
                                               Nothing -> sendCommand NackCommand
                                               Just (mk, sd, name) -> shareMasterKey mk sd name
      Right (ChangePasswordCommand newpw) -> do ok <- lift $ changeServicePassword conn serviceName newpw
                                                sendAckNack ok
      Right ListUsersCommand -> do users <- lift $ listUsersForService conn serviceName
                                   sendCommand $ AccountNamesCommand users
      Right (SetServiceDataCommand u sd) -> do ok <- lift $ setServiceData conn serviceName u sd
                                               sendAckNack ok
      Right (GetServiceDataCommand u) -> do sd <- lift $ getServiceData conn serviceName u
                                            sendCommand $ ServiceDataCommand sd
      _ -> sendCommand NackCommand

sendAckNack :: Bool -> StateT SecureChannel IO ()
sendAckNack b = do
   if b
      then sendCommand AckCommand
      else sendCommand NackCommand

ensurePriv :: Connection -> String -> StateT SecureChannel IO () -> StateT SecureChannel IO ()
ensurePriv conn user func = do
   adm <- lift $ isAdmin conn user
   if adm
      then func
      else sendCommand NackCommand

serveUserRequests :: Connection -> String -> StateT SecureChannel IO ()
serveUserRequests conn user = forever $ do
   request <- chanGetLine
   case (parseCommand request) of
      -- Privileged commands
      Right (AddUserCommand newUser pw) -> ensurePriv conn user $ do
                                               ok <- lift $ addUser conn newUser pw
                                               sendAckNack ok
      Right (AddServiceCommand name pw) -> ensurePriv conn user $ do
                                               ok <- lift $ addService conn name pw
                                               sendAckNack ok
      Right (AddServiceSecureCommand name) -> ensurePriv conn user $ do
                                                  mPw <- lift $ addServiceSecure conn name
                                                  case mPw of
                                                     Just pw -> sendCommand $ ServicePasswordIsCommand pw
                                                     Nothing -> sendCommand NackCommand
      Right (DelUserCommand name) -> ensurePriv conn user $ do
                                         ok <- lift $ deleteUser conn name
                                         sendAckNack ok
      Right (DelServiceCommand name) -> ensurePriv conn user $ do
                                          ok <- lift $ deleteService conn name
                                          sendAckNack ok
      Right (ListUsersCommand) -> ensurePriv conn user $ do
                                     users <- lift $ listUsers conn
                                     sendCommand $ AccountNamesCommand users
      Right ListServicesCommand -> ensurePriv conn user $ do
                                     services <- lift $ listServices conn
                                     sendCommand $ AccountNamesCommand services
      Right (AllowCommand u s) -> ensurePriv conn user $ do
                                     ok <- lift $ allowUserForService conn u s
                                     sendAckNack ok
      Right (DenyCommand u s) -> ensurePriv conn user $ do
                                     ok <- lift $ denyUserForService conn u s
                                     sendAckNack ok
      Right (ServicesForUserCommand u) -> ensurePriv conn user $ do
                                             svcs <- lift $ listServicesForUser conn u
                                             sendCommand $ AccountNamesCommand svcs
      Right (UsersForServiceCommand svc) -> ensurePriv conn user $ do
                                               users <- lift $ listUsersForService conn svc
                                               sendCommand $ AccountNamesCommand users
      Right (SetPasswordCommand u pw) -> ensurePriv conn user $ do
                                             ok <- lift $ changeUserPassword conn u pw
                                             sendAckNack ok
      Right (SetUserOTPSecretCommand u s) -> ensurePriv conn user $ do
                                                 ok <- lift $ setOTP' conn u s
                                                 sendAckNack ok
      Right (DisableUserOTPCommand u) -> ensurePriv conn user $ do
                                             ok <- lift $ disableOTP' conn u
                                             sendAckNack ok
      -- Unprivileged commands
      Right (ChangePasswordCommand newpw) -> do ok <- lift $ changeUserPassword conn user newpw
                                                sendAckNack ok
      Right (SetOTPSecretCommand s) -> do ok <- lift $ setOTP' conn user s
                                          sendAckNack ok
      Right (DisableOTPCommand) -> do ok <- lift $ disableOTP' conn user
                                      sendAckNack ok
      -- Unknown commands?
      _ -> sendCommand NackCommand

serverMain :: Connection -> String -> Int -> IO ()
serverMain conn localAddr localPort = do
   TCP.forkingTcpServer localAddr localPort handler
   where handler tcpConn = do logInfo $ "Connection accepted."
                              let chan = handleToChannel $ TCP.connHandle tcpConn
                              handleNetworkConnection chan conn


data Options = Options {
     databaseDir  :: FilePath
   , databaseFile :: FilePath
   , listenPort   :: Int
   , listenHost   :: String
   } deriving (Show)

defaultOptions :: Options
defaultOptions = Options {
     databaseDir  = "."
   , databaseFile = "accounts.sqlite3"
   , listenPort   = 1234
   , listenHost   = "0.0.0.0"
   }

options :: [OptDescr (Options -> Options)]
options = [
     Option ['d'] ["databaseDir"]  (ReqArg (\s opts -> opts { databaseDir = s }) "DIR")      "set database directory"
   , Option ['f'] ["databaseFile"] (ReqArg (\s opts -> opts { databaseFile = s }) "FILE")    "set database file name"
   , Option ['p'] ["port"]         (ReqArg (\s opts -> opts { listenPort = read s }) "PORT") "set listen port"
   , Option ['l'] ["listen"]       (ReqArg (\s opts -> opts { listenHost = s }) "HOST")      "set listen address"
   ]

getOptions :: [String] -> IO Options
getOptions args =
   case getOpt Permute options args of
      (o,[],[])    -> return $ Prelude.foldl (flip id) defaultOptions o
      (_,(u:us),_) -> ioError (userError ("Unknown option detected.\n" ++ usageInfo header options))
      (_,[],errs)  -> ioError (userError (Prelude.concat errs ++ usageInfo header options))
   where header = "Usage:"

main = do
   opts <- getArgs >>= getOptions
   conn <- openDatabase (databaseDir opts </> databaseFile opts)
   logInfo "Starting server."
   serverMain conn (listenHost opts) (listenPort opts)
