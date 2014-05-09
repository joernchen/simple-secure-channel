{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
A CredentialsProvider is a thing that can hand over user names and
passwords. The reason we need such a thing is that the J-PAKE protocol allows
to make use of low-entropy passwords. In order to prevent brute-force
attacks, a CredentialsProvider applies rate-limiting when failed
authentication attempts occur. 

This module implements a simple CredentialsProvider,
which makes use of a sqlite3 database to keep track of failed login attempts.
With each failed attempt, an exponentially growing delay is introduced.
-}

module Crypto.Util.CredentialsProvider
   (CredentialsProvider, genCredentialsProvider,
    getUser, getPassword, failLogin, succeedLogin
   )
where

import Prelude
import Control.Monad (when)
import System.Directory
import System.FilePath
import Database.HDBC 
import Database.HDBC.Sqlite3
import Data.Time.Clock.POSIX
import Control.Exception
import Control.Concurrent (threadDelay)
import Crypto.Util.Encoding

-- | A credentials provider
data CredentialsProvider = CredentialsProvider {
      -- | Get the user name for a particular service.
      getUser       :: String -> IO String 
      ,getPassword' :: String -> String -> IO String
      ,getOtp       :: String -> String -> IO String
      ,askUseOtp    :: String -> String -> IO Bool
      ,dbName       :: String
   }


-- |Tell the CredentialsProvider that a failed login attempt has been observed.
failLogin :: CredentialsProvider -- ^ The CredentialsProvider
             -> String -- ^ The user name
             -> String -- ^ The name of the observing service
             -> IO ()
failLogin prov user service =
   failLogin' (dbName prov) user service

-- |Tell the CredentialsProvider that a login attempt has succeeded.
succeedLogin :: CredentialsProvider -- ^ The CredentialsProvider
                -> String -- ^ The user name
                -> String -- ^ The name of the observing service
                -> IO ()
succeedLogin prov user service = do
   succeedLogin' (dbName prov) user service

-- |Look up the password of a user. This might not return anything useful,
-- either because the user is unknown or because the user is currently
-- rate-limited.
getPassword :: CredentialsProvider -- ^ The CredentialsProvider
               -> String -- ^ The user name
               -> String -- ^ The name of the requesting service
               -> IO (Maybe String) -- ^ Maybe the user's password
getPassword prov user service = do
   firstTime <- not `fmap` isAccountPresent (dbName prov) user service
   when firstTime $ do
      saveAccount (dbName prov) user service
      otp <- (askUseOtp prov) user service
      _   <- setAccountOTP (dbName prov) user service otp
      return ()
   to <- getTimeout (dbName prov) user service
   if (to > 0)
      then return Nothing
      else do
         pwd <- (getPassword' prov) user service
         doOtp <- getAccountOtp (dbName prov) user service
         ret <- if doOtp
                     then do otp <- (getOtp prov) user service
                             return $ Just $ pwd <||> otp
                     else return $ Just pwd
         return ret

-- |Build a simple CredentialsProvider. This provider will make use of a sqlite3
-- database to keep track of failed and successful login attempts. The database
-- will be stored beneath the user's home directory under the name
-- .jpakePasswordStore/block.sqlite3.
genCredentialsProvider :: (String -> IO String) -- ^ An IO action for obtaining 
                                                -- the user name 
                                                -- (could be getLine in many 
                                                -- cases). The action takes
                                                -- the name of the service to
                                                -- authenticate to as an
                                                -- argument.
                          -> (String -> String -> IO String) -- ^ An IO action 
                                                             -- for obtaining 
                                                             -- the password of
                                                             -- a user for a
                                                             -- particular
                                                             -- service.
                          -> (String -> String -> IO Bool) -- ^ An IO action for 
                                                           -- asking the user if
                                                           -- they would
                                                           -- like to use OTP
                                                           -- when an account is
                                                           -- first created.
                          -> (String -> String -> IO String) -- ^ An IO action 
                                                             -- for asking for 
                                                             -- the user's OTP
                                                             -- password (if
                                                             -- needed)
                          -> IO CredentialsProvider -- ^ The CredentialsProvider
genCredentialsProvider gu gp useOtp getOtp' = do
   hd <- getHomeDirectory
   let dir = hd </> ".jpakePasswordStore"
   createDirectoryIfMissing False dir
   (openDatabase $ dir </> "block.sqlite3") >>= disconnect
   return $ CredentialsProvider {   getUser = gu
                                  , getPassword' = gp
                                  , dbName = dir </> "block.sqlite3"
                                  , getOtp = getOtp'
                                  , askUseOtp = useOtp 
                                }

getTime :: IO Integer
getTime = do 
   x <- getPOSIXTime
   return $ round x

setupDatabase :: Connection -> IO ()
setupDatabase conn = do
   _ <- run conn "CREATE TABLE fail (user TEXT, service TEXT, \
                 \otp INTEGER default 0, failed INTEGER default 0, \
                 \lastFail INTEGER, PRIMARY KEY(user, service))" []
   commit conn

saveAccount' :: Connection -> String -> String -> IO ()
saveAccount' conn user service = do
   _ <- run conn "INSERT OR IGNORE INTO fail(user, service) VALUES (?,?)" 
            [toSql user, toSql service]
   return ()

saveAccount :: String -> String -> String -> IO ()
saveAccount name user service = withDatabase name $ \conn -> do
   saveAccount' conn user service

failLogin' :: String -> String -> String -> IO ()
failLogin' name user service = withDatabase name $ \conn -> do
   saveAccount' conn user service -- Better safe than sorry..
   _ <- run conn "UPDATE fail SET failed = failed + 1, \
                 \lastFail = strftime('%s','now') \
                 \WHERE user = ? AND service = ?" 
            [toSql user, toSql service]
   return ()

setAccountOTP :: String -> String -> String -> Bool -> IO Bool
setAccountOTP name user service doOtp = withDatabase name $ \conn -> do
   let otp = if doOtp then 1 else 0 :: Int
   cnt <- run conn "UPDATE fail SET otp=? WHERE user=? AND service=?" 
          [toSql otp, toSql user, toSql service]
   return $ cnt /= 0

isAccountPresent :: String -> String -> String -> IO Bool
isAccountPresent name user service = withDatabase name $ \conn -> do
   rows <- quickQuery' conn "SELECT user FROM fail WHERE user=? AND service=?" 
                       [toSql user, toSql service]
   return $ length rows /= 0

getAccountOtp :: String -> String -> String -> IO Bool
getAccountOtp name user service = withDatabase name $ \conn -> do
   rows <- quickQuery' conn "SELECT user FROM fail WHERE user=? AND service=? \
                            \AND otp=1" 
                       [toSql user, toSql service]
   return $ length rows /= 0

getTimeout :: String -> String -> String -> IO Integer
getTimeout name user service = withDatabase name $ \conn -> do
   saveAccount' conn user service -- Better safe than sorry..
   rows <- quickQuery' conn "SELECT failed, lastFail FROM fail WHERE user = ? \
                            \AND service = ?" 
                       [toSql user, toSql service]
   let [failed, lastFail] = map fromSql (rows !! 0) :: [Integer]
   let delta = 4 * (2^failed)
   curTime <- getTime
   if failed == 0 || curTime > lastFail + delta
      then return 0
      else return $ delta - curTime + lastFail

succeedLogin' :: String -> String -> String -> IO ()
succeedLogin' name user service = withDatabase name $ \conn -> do
   saveAccount' conn user service -- Better safe than sorry..
   _ <- run conn "UPDATE fail SET failed = 0, lastFail = 0 WHERE user = ? AND \
                 \service = ?" 
            [toSql user, toSql service]
   return ()

openDatabase :: String -> IO Connection
openDatabase fileName = do
   e <- doesFileExist fileName
   mConn <- tryConnect fileName 10
   case mConn of
      Nothing -> error "Cannot open database."
      Just conn -> do when (not e) (setupDatabase conn)
                      commit conn
                      setBusyTimeout conn 2000
                      return conn

tryConnect :: String -> Int -> IO (Maybe Connection)
tryConnect _ 0 = return Nothing
tryConnect fileName tries =
   (Just `fmap` connectSqlite3 fileName) `catch` handler
   where handler :: SomeException -> IO (Maybe Connection)
         handler _ = do threadDelay 100000
                        tryConnect fileName (tries - 1)

withDatabase :: String -> (Connection -> IO a) -> IO a
withDatabase name func = do
   conn <- openDatabase name
   ret <- func conn
   commit conn
   disconnect conn
   return ret
