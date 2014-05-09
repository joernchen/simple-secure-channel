{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

module Network.AAA.Protocol (Command(..), parseCommand, serialize)
where

import Text.ParserCombinators.Parsec 
import qualified Codec.Binary.Base64.String as B64
import qualified Data.ByteString.Base64 as BS
import qualified Data.ByteString.Char8 as C8
import Data.ByteString hiding (count, map, intercalate)
import Data.List (intercalate)

encode :: String -> String
encode = Prelude.filter (/= '\n') . B64.encode

decode :: String -> String
decode = B64.decode

bsEncode :: ByteString -> String
bsEncode = Prelude.filter (/= '\n') . C8.unpack . BS.encode

bsDecode :: String -> Either String ByteString
bsDecode = BS.decode . C8.pack

-- |A command as understood by the AAA server and/or its client
data Command = AuthUserCommand -- ^ Send this command in order to indicate that 
                               -- a J-PAKE key exchange for a user will follow. 
                               -- Use this to login on the AAA server.
             | AuthServiceCommand -- ^ The same as AuthUserCommand, but the 
                                  -- following key exchange is for a service 
                                  -- (i.e. a service logs in on the AAA server).
             | AuthUserForServiceCommand -- ^ This command is sent by a service 
                                         -- that passes the J-PAKE key exchange 
                                         -- data from a user to the AAA service.
                                         -- The AAA server will handle the 
                                         -- subsequent key exchange messages and
                                         -- then send an "AuthSuccessCommand" to
                                         -- the service.
             | ChangePasswordCommand String -- ^ Change your own password (after
                                            -- being logged in).
             | SetServiceDataCommand String String -- ^ Used by services to set
                                                   -- the authorization 
                                                   -- information for a user.
             | AckCommand -- ^ ACK
             | NackCommand -- ^ NACK
             | AuthSuccessCommand ByteString String String -- ^ Sent by the AAA 
                                                 -- service once an 
                                                 -- "AuthUserForServiceCommand" 
                                                 -- was successful. It
                                                 -- returns the master
                                                 -- key, the service 
                                                 -- data and the user 
                                                 -- name sent in the 
                                                 -- key exchange.
             | AddUserCommand String String -- ^ Add a user and set their 
                                            -- password.
             | AddServiceCommand String String -- ^ Add a service and set its 
                                               -- password.
             | AddServiceSecureCommand String -- ^ Add a service with an 
                                              -- automatically generated 
                                              -- password. This service will not
                                              -- be subject to rate-limiting 
                                              -- when password brute-forcing is
                                              -- observed. Returns a
                                              -- "ServicePasswordIsCommand".
             | DelUserCommand String -- ^ Delete a user
             | DelServiceCommand String -- ^ Delete a service.
             | ListUsersCommand -- ^ List all users. Returns an 
                                -- "AccountNamesCommand".
             | ListServicesCommand -- ^ List all services. Returns an 
                                   -- "AccountNamesCommand".
             | AccountNamesCommand [String] -- ^ A list of user or service 
                                            -- names. Sent as a response to a 
                                            -- number of query commands by the 
                                            -- AAA service.
             | AllowCommand String String -- ^ Allow a user access to a service.
             | DenyCommand String String -- ^ Deny a user to access a service.
             | ServicesForUserCommand String -- ^ List all services the 
                                             -- specified user can access. 
                                             -- Returns an 
                                             -- "AccountNamesCommand".
             | UsersForServiceCommand String -- ^ List all users known to the 
                                             -- specified service. Returns an 
                                             -- "AccountNamesCommand".
             | GetServiceDataCommand String -- ^ Get the service data for a 
                                            -- service. Returns a 
                                            -- "ServiceDataCommand".
             | ServiceDataCommand String -- ^ Contains the service data queried 
                                         -- by "GetServiceDataCommand".
             | ServicePasswordIsCommand String -- ^ Returns the service password
                                               -- generated by 
                                               -- "AddServiceSecureCommand".
             | SetPasswordCommand String String -- ^ Set the password for the 
                                                -- specified user.
             | SetOTPSecretCommand String -- ^ Set the OTP secret for the 
                                          -- current user.
             | SetUserOTPSecretCommand String String -- ^ Set the OTP secret for
                                                     -- the specified user.
             | DisableOTPCommand -- ^ Disable OTP for the current user.
             | DisableUserOTPCommand String -- ^ Disable OTP for the specified 
                                            -- user.

auth_user :: String
auth_user        = "AUTH_USER"

auth_service :: String
auth_service     = "AUTH_SERVICE"

change_pw :: String
change_pw        = "CHANGE_PW"

set_service_data :: String
set_service_data = "SET_SERVICE_DATA"

auth_user_for_service :: String
auth_user_for_service = "AUTH_USER_FOR_SERVICE"

nack :: String
nack             = "NACK"

ack :: String
ack              = "ACK"

auth_success :: String
auth_success     = "AUTH_SUCCESS"

add_user :: String
add_user         = "ADD_USER"

add_service :: String
add_service      = "ADD_SERVICE"

del_user :: String
del_user         = "DELETE_USER"

del_service :: String
del_service      = "DELETE_SERVICE"

list_users :: String
list_users       = "LIST_USERS"

list_services :: String
list_services    = "LIST_SERVICES"

account_names :: String
account_names    = "ACCOUNT_NAMES"

allow :: String
allow            = "ALLOW"

deny :: String
deny             = "DENY"

services_for_user :: String
services_for_user= "SERVICES_FOR_USER"

users_for_service :: String
users_for_service= "USERS_FOR_SERVICE"

get_service_data :: String
get_service_data = "GET_SERVICE_DATA"

service_data_is :: String
service_data_is  = "SERVICE_DATA_IS"

add_service_sec :: String
add_service_sec  = "ADD_SERVICE_SECURE"

service_pw_is :: String
service_pw_is    = "SERVICE_PASSWORD_IS"

set_password :: String
set_password     = "SET_PASSWORD"

set_otp :: String
set_otp          = "SET_OTP"

set_user_otp :: String
set_user_otp     = "SET_USER_OTP"

disable_otp :: String
disable_otp      = "DISABLE_OTP"

disable_user_otp :: String
disable_user_otp = "DISABLE_USER_OTP"

instance Show Command where
   show (AuthUserCommand)               = auth_user
   show (AuthServiceCommand)            = auth_service
   show (AuthUserForServiceCommand)     = auth_user_for_service
   show (ChangePasswordCommand pw)      = change_pw ++ " " ++ pw
   show (SetServiceDataCommand user sd) = set_service_data ++ " " ++ user ++ " " 
                                                           ++ sd
   show (AckCommand)                    = ack
   show (NackCommand)                   = nack
   show (AuthSuccessCommand _ sd na)    = auth_success ++ " _MASTER_KEY_HERE_ " 
                                                       ++ sd ++ " " ++ na
   show (AddUserCommand user _)         = add_user ++ " " ++ user 
                                                   ++ " _PW_HERE_"
   show (AddServiceCommand name _)      = add_service ++ " " ++ name 
                                                      ++ " _PW_HERE_"
   show (DelUserCommand user)           = del_user ++ " " ++ user
   show (DelServiceCommand name)        = del_service ++ " " ++ name
   show (ListUsersCommand)              = list_users
   show (ListServicesCommand)           = list_services
   show (AccountNamesCommand names)     = account_names ++ " " 
                                                      ++ (intercalate " " names)
   show (AllowCommand user service)     = allow ++ " " ++ user ++ " " ++ service
   show (DenyCommand user service)      = deny ++ " " ++ user ++ " " ++ service
   show (ServicesForUserCommand user)   = services_for_user ++ " " ++ user
   show (UsersForServiceCommand name)   = users_for_service ++ " " ++ name
   show (GetServiceDataCommand user)    = get_service_data ++ " " ++ user
   show (ServiceDataCommand sd)         = service_data_is ++ " " ++ sd
   show (AddServiceSecureCommand name)  = add_service_sec ++ " " ++ name
   show (ServicePasswordIsCommand _)    = service_pw_is ++ " _PW_HERE_"
   show (SetPasswordCommand user _)     = set_password ++ " " ++ user 
                                                       ++ " _PW_HERE_"
   show (SetOTPSecretCommand _)         = set_otp ++ " _SECRET_"
   show (SetUserOTPSecretCommand u _)   = set_user_otp ++ " " ++ u 
                                                       ++ " _SECRET_"
   show (DisableOTPCommand)             = disable_otp
   show (DisableUserOTPCommand u)       = disable_user_otp ++ " " ++ u

-- |Serialize a "Command" into a String. This function can be used to send out a
-- command over the network. The protocol is line-oriented. Therefore, you
-- should send a trailing newline after each command.
serialize :: Command -> String
serialize AuthUserCommand                 = auth_user
serialize AuthServiceCommand              = auth_service
serialize AuthUserForServiceCommand       = auth_user_for_service
serialize (ChangePasswordCommand pw)      = change_pw ++ " " ++ (encode pw)
serialize (SetServiceDataCommand user sd) = set_service_data ++ " " 
                                             ++ (encode user) ++ " " 
                                             ++ (encode sd)
serialize (AuthSuccessCommand mk sd na)   = auth_success ++ " " ++ (bsEncode mk) 
                                             ++ " " 
                                             ++ (encode $ show sd) 
                                             ++ " " ++ (encode na)
serialize (AckCommand)                    = ack
serialize (NackCommand)                   = nack
serialize (AddUserCommand user pw)        = add_user ++ " " ++ (encode user) 
                                             ++ " " ++ (encode pw)
serialize (AddServiceCommand name pw)     = add_service ++ " " ++ (encode name) 
                                             ++ " " ++ (encode pw)
serialize (DelUserCommand user)           = del_user ++ " " ++ (encode user)
serialize (DelServiceCommand name)        = del_service ++ " " ++ (encode name)
serialize (ListUsersCommand)              = list_users
serialize (ListServicesCommand)           = list_services
serialize (AccountNamesCommand names)     = account_names ++ " " ++ 
                                            (intercalate " " $ map encode names)
serialize (AllowCommand user service)     = allow ++ " " ++ (encode user) ++ " "
                                             ++ (encode service)
serialize (DenyCommand user service)      = deny ++ " " ++ (encode user) ++ " " 
                                             ++ (encode service)
serialize (ServicesForUserCommand user)   = services_for_user ++ " " 
                                             ++ (encode user)
serialize (UsersForServiceCommand name)   = users_for_service ++ " " 
                                             ++ (encode name)
serialize (GetServiceDataCommand user)    = get_service_data ++ " " 
                                             ++ (encode user)
serialize (ServiceDataCommand sd)         = service_data_is ++ " " 
                                             ++ (encode sd)
serialize (AddServiceSecureCommand name)  = add_service_sec ++ " " 
                                             ++ (encode name)
serialize (ServicePasswordIsCommand pw)   = service_pw_is ++ " " 
                                             ++ (encode pw)
serialize (SetPasswordCommand user pw)    = set_password ++ " " ++ (encode user)
                                             ++ " " ++ (encode pw)
serialize (SetOTPSecretCommand s)         = set_otp ++ " " ++ (encode s)
serialize (SetUserOTPSecretCommand u s)   = set_user_otp ++ " " ++ (encode u) 
                                             ++ " " ++ (encode s)
serialize (DisableOTPCommand)             = disable_otp
serialize (DisableUserOTPCommand u)       = disable_user_otp ++ " " 
                                             ++ (encode u)

-- |Parse a received command string. The protocol is line-oriented, therefore
-- reading command strings from the network should be straight-forward.
parseCommand :: String -> Either ParseError Command
parseCommand x = parse command "Command request" x

type CommandParser = GenParser Char () Command

command :: CommandParser
command =
   try authUserCommand
   <|> try authServiceCommand
   <|> try authUserForServiceCommand
   <|> try changePasswordCommand
   <|> try setServiceDataCommand
   <|> try authSuccessCommand
   <|> try ackCommand
   <|> try nackCommand
   <|> try addUserCommand
   <|> try addServiceCommand
   <|> try delUserCommand
   <|> try delServiceCommand
   <|> try listUsersCommand
   <|> try listServicesCommand
   <|> try accountNamesCommand
   <|> try allowCommand
   <|> try denyCommand
   <|> try servicesForUserCommand
   <|> try usersForServiceCommand
   <|> try getServiceDataCommand
   <|> try serviceDataCommand
   <|> try addServiceSecureCommand
   <|> try servicePasswordIsCommand
   <|> try setPasswordCommand
   <|> try setOtpCommand
   <|> try setUserOtpCommand
   <|> try disableOtpCommand
   <|> try disableUserOtpCommand

authUserCommand :: CommandParser
authUserCommand           = justCommand   auth_user             AuthUserCommand

ackCommand :: CommandParser
ackCommand                = justCommand   ack                   AckCommand

nackCommand :: CommandParser
nackCommand               = justCommand   nack                  NackCommand

authServiceCommand :: CommandParser
authServiceCommand        = justCommand   auth_service          
                                          AuthServiceCommand

authUserForServiceCommand :: CommandParser
authUserForServiceCommand = justCommand   auth_user_for_service 
                                          AuthUserForServiceCommand

changePasswordCommand :: CommandParser
changePasswordCommand     = oneArgCommand change_pw             
                                          ChangePasswordCommand

setServiceDataCommand :: CommandParser
setServiceDataCommand     = twoArgCommand set_service_data      
                                          SetServiceDataCommand

authSuccessCommand :: CommandParser
authSuccessCommand        = do
   _ <- justCommand auth_success (AuthSuccessCommand C8.empty "" "")
   skipSpaces1
   mk <- parseBSArg
   skipSpaces1
   sd <- parseArg
   skipSpaces1
   name <- parseArg
   return $ AuthSuccessCommand mk (read sd) name

addUserCommand :: CommandParser
addUserCommand            = twoArgCommand add_user           AddUserCommand

addServiceCommand :: CommandParser
addServiceCommand         = twoArgCommand add_service        AddServiceCommand

delUserCommand :: CommandParser
delUserCommand            = oneArgCommand del_user           DelUserCommand

delServiceCommand :: CommandParser
delServiceCommand         = oneArgCommand del_service        DelServiceCommand

listUsersCommand :: CommandParser
listUsersCommand          = justCommand   list_users         ListUsersCommand

listServicesCommand :: CommandParser
listServicesCommand       = justCommand   list_services      ListServicesCommand

accountNamesCommand :: CommandParser
accountNamesCommand = do
   _ <- justCommand account_names (AccountNamesCommand [])
   names <- many $ do skipSpaces1
                      parseArg
   return $ AccountNamesCommand names

allowCommand :: CommandParser
allowCommand              = twoArgCommand allow                 AllowCommand

denyCommand :: CommandParser
denyCommand               = twoArgCommand deny                  DenyCommand

usersForServiceCommand :: CommandParser
usersForServiceCommand    = oneArgCommand users_for_service     
                                          UsersForServiceCommand

servicesForUserCommand :: CommandParser
servicesForUserCommand    = oneArgCommand services_for_user     
                                           ServicesForUserCommand

getServiceDataCommand :: CommandParser
getServiceDataCommand     = oneArgCommand get_service_data      
                                          GetServiceDataCommand

serviceDataCommand :: CommandParser
serviceDataCommand        = oneArgCommand service_data_is       
                                          ServiceDataCommand

addServiceSecureCommand :: CommandParser
addServiceSecureCommand   = oneArgCommand add_service_sec       
                                          AddServiceSecureCommand

servicePasswordIsCommand :: CommandParser
servicePasswordIsCommand  = oneArgCommand service_pw_is         
                                          ServicePasswordIsCommand

setPasswordCommand :: CommandParser
setPasswordCommand        = twoArgCommand set_password          
                                          SetPasswordCommand

setOtpCommand :: CommandParser
setOtpCommand             = oneArgCommand set_otp        SetOTPSecretCommand

setUserOtpCommand :: CommandParser
setUserOtpCommand         = twoArgCommand set_user_otp   SetUserOTPSecretCommand

disableOtpCommand :: CommandParser
disableOtpCommand         = justCommand disable_otp      DisableOTPCommand

disableUserOtpCommand :: CommandParser
disableUserOtpCommand     = oneArgCommand disable_user_otp DisableUserOTPCommand

justCommand :: String -> Command -> CommandParser
justCommand cmd constr = 
   commandAndArgs cmd 0 >> return constr

oneArgCommand :: String -> (String -> Command) -> CommandParser
oneArgCommand cmd constr = do
   (arg:[]) <- commandAndArgs cmd 1
   return $ constr arg

twoArgCommand :: String -> (String -> String -> Command) -> CommandParser
twoArgCommand cmd constr = do
   (arg1:arg2:[]) <- commandAndArgs cmd 2
   return $ constr arg1 arg2

commandAndArgs :: String -> Int -> GenParser Char st [String]
commandAndArgs cmd argCount = do
   _ <- string cmd
   lookAhead ((space >> return ()) <|> eof)
   count argCount $ do
      skipSpaces1
      arg <- parseArg
      return $ arg

parseArg :: GenParser Char st String
parseArg = do
   p <- many $ oneOf $ ['A'..'Z'] ++ ['a'..'z'] ++ ['0'..'9'] ++ "/+="
   return $ decode p

parseBSArg :: GenParser Char st ByteString
parseBSArg = do
   p <- many $ oneOf $ ['A'..'Z'] ++ ['a'..'z'] ++ ['0'..'9'] ++ "/+="
   case (bsDecode p) of
      Left _ -> return C8.empty
      Right bs -> return bs

skipSpaces1 :: GenParser Char st ()
skipSpaces1 = skipMany1 $ char ' '
