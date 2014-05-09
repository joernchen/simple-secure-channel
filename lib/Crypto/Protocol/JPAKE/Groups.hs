{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-# LANGUAGE DeriveGeneric #-}

module Crypto.Protocol.JPAKE.Groups (
      MultGroup, (<**>), (<*>), sameGroup, neutral, invert,
      SubgroupGenerator(..), ModPGroup,
      JPAKEGroup(..), rfc5114_modp_2048_256
   ) where

import Data.List
import Crypto.Util.ConstantTime
import Control.DeepSeq.Generics
import GHC.Generics

-- |An element of a multiplicative group. This is not really ideal, as
-- we actually should introduce separate groups on a type level (e.g.,
-- Z/7Z != Z/5Z. However, to do that, we'd need dependent types (possibly
-- not for simple modp groups, but we want to stay as general as possible).
-- Therefore, we have the sameGroup and the neutral function, which operate
-- on group level, rather than on element level.
class (Show a, Eq a, NFData a) => MultGroup a where
   -- |The group operation. We call it multiplication, as we're thinking in
   -- terms of multiplicative groups. You should implement, but not invoke
   -- the function. Use (<*>) below.
   mult' :: a -> a -> a
   -- |Multiply two group elements.
   (<*>)  :: a -> a -> a
   x <*> y | sane x && sane y = mult' x y
           | otherwise = error "Bad group element."
   
   -- |Return the neutral element of the group. You need to implement this
   -- function.
   neutral :: a -> a

   -- |Invert a group element. You should implement, but not invoke the
   -- function. Use invert below.
   invert' :: a -> a
   -- |Invert a group element.
   invert :: a -> a
   invert x | sane x = invert' x
            | otherwise = error "Bad group element."

   -- |The square and multiply algorithm for computing exponentials. Do not
   -- invoke it yourself.
   squareMultiply :: a -> Integer -> a
   squareMultiply y z | z == 0 = neutral y
                      | otherwise = let arg1 = constantChoice (even z) (y <*> y) 
                                                              y
                                        arg2 = constantChoice (even z) 
                                                              (z `div` 2) 
                                                              (z-1)
                                        res  = squareMultiply arg1 arg2
                                    in
                                    constantChoice (even z) (res) (y <*> res)

   -- |Take a to the power of n.
   (<**>) :: a -> Integer -> a
   a <**> n | not (sane a) = error "Bad group element."
            | otherwise =  let arg = constantChoice (n >= 0) (fromIntegral n) 
                                                    (fromIntegral (-n))
                               res = squareMultiply a arg
                           in constantChoice (n >= 0) res (invert res)

   -- |Return true iff the provided elements are from the same group. You have
   -- to implement this function.
   sameGroup :: a -> a -> Bool
   -- |Verify the a provided group element is well-formed. You have to implement
   -- this function.
   sane :: a -> Bool
   
-- Multiplicative group mod p
gcdExt :: Integer -> Integer -> (Integer, Integer, Integer)
gcdExt a 0 = (1, 0, a)
gcdExt a b = let (q, r) = a `quotRem` b
                 (s, t, g) = gcdExt b r
             in (t, s - q * t, g)

-- |A generator of a subgroup.
data SubgroupGenerator a = SubgroupGenerator {
      generatorValue    :: a, -- ^ The actual generator value
      subgroupOrder     :: Integer -- ^ The order of the generated subgroup
   } deriving (Show, Read, Eq)

modInv :: Integer -> Integer -> Integer
modInv a m = let (i, _, 1) = gcdExt a m
             in if i < 0 
                  then fromIntegral $ i + m 
                  else fromIntegral $ i

-- |The integers modulo a prime form a multiplicative group.
data ModPGroup = ModPGroup { modulus :: Integer,
                             value   :: Integer} deriving(Eq, Generic)

instance NFData ModPGroup where rnf = genericRnf

instance Show ModPGroup where
   show x | (modulus x == prime1) && (value x == gen1) = "rfc5114_modp_2048_\
                                                         \256_gen"
          | (modulus x == prime1) = "rfc5114_modp_2048_256(" ++ show (value x) 
                                    ++ ")"
          | otherwise = "MODP(" ++ (show $ modulus x) ++ "," ++ 
                        (show $ value x) ++ ")"

-- XXX TODO: This Read instance is more than creepy. But it works for now.
instance Read ModPGroup where
   readsPrec i x = rp_worker i (dropWhile (==' ') x)

rp_worker :: Int -> String -> [(ModPGroup, String)]
rp_worker    i x | "rfc5114_modp_2048_256_gen" `isPrefixOf` x = [(ModPGroup {modulus = prime1, value = gen1}, drop 25 x)]
                 | "rfc5114_modp_2048_256(" `isPrefixOf` x && ')' `elem` x = 
                        let start   = dropWhile (/= '(') x
                            content = drop 1 $ takeWhile (/= ')') start
                            rest    = drop 1 $ dropWhile (/=')') x
                        in [(ModPGroup {
                                modulus = prime1
                              , value = (read content)
                             }, rest)]
                 | "MODP(" `isPrefixOf` x && ')' `elem` x =
                        let start          = dropWhile (/= '(') x
                            [((m,v),rest)] = readsPrec i start
                        in [(ModPGroup {modulus = m, value = v}, rest)]
                 | otherwise = []

instance MultGroup ModPGroup where
   mult' (ModPGroup n a) (ModPGroup m b) | (n == m) && sane (ModPGroup n a) && sane (ModPGroup m b) = ModPGroup n ((a * b) `mod` n)
                                         | otherwise = error "You cannot multiply elements of different groups."
   invert' (ModPGroup n a) = ModPGroup n (modInv (fromIntegral a) (fromIntegral n))

   neutral (ModPGroup n _) = ModPGroup n 1
   sameGroup (ModPGroup n _) (ModPGroup m _) = n == m
   sane (ModPGroup n a) | (a >= 0)  = (a < n)
                        | otherwise = (-a < n) 

-- |The description of a group that J-PAKE can be run on.
data JPAKEGroup a = JPAKEGroup {
      jpakeGroupGenerator :: SubgroupGenerator a
   }

------------------------ Well-known groups -------------------------------------

-- http://tools.ietf.org/html/rfc5114#section-2.3
-- 2048-bit MODP Group with 256-bit Prime Order Subgroup
prime1 :: Integer
prime1 = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
gen1 :: Integer
gen1 = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
order1 :: Integer
order1 = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

-- |The 2048 bit MODP group from rfc5114, section-2.3.
rfc5114_modp_2048_256 :: JPAKEGroup ModPGroup
rfc5114_modp_2048_256 = JPAKEGroup {
      jpakeGroupGenerator = SubgroupGenerator { 
                                generatorValue = ModPGroup prime1 gen1
                              , subgroupOrder = order1
                            }
   }
