{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
The J-PAKE protocol, as described in <https://eprint.iacr.org/2010/190.pdf>.
J-PAKE is a key exchange protocol offering mutual authentication based on a
shared (possibly low-entropy) password, resistance against on- and off-line
dictionary attacks, forward secrecy and known session security. The protocol is
provably secure under standard intractability assumptions. Further, the protocol
can be instantiated over any group where the DDH problem is intractable,
including MODP-groups and elliptic curves.
-}

module Crypto.Protocol.JPAKE (JPAKESecret(..), JPAKE(..), DLZKP(..),
                              buildJPAKEStage1, buildJPAKEStage2, 
                              verifyJPAKEStage1, verifyJPAKEStage2, deriveKey, 
                              buildDLZKP, verifyDLZKP) 
where

import qualified Data.Binary as Bin
import Data.ByteString.Lazy hiding (pack, map)
import Data.ByteString.Lazy.Char8 (pack)
import Crypto.Protocol.JPAKE.Groups

-- |A Zero Knowledge Proof based on Schnorr's signature scheme.
data DLZKP a = 
   DLZKP { generator :: SubgroupGenerator a,
           expValue :: a,
           signerID :: String,
           verifier :: a,
           rvalue   :: Integer
         } deriving (Show, Read)

binToInt :: ByteString -> Integer
binToInt = Data.ByteString.Lazy.foldl ( \x y -> x * 256 + (fromIntegral y)) 0

-- |Build a Zero Knowledge Proof. 
buildDLZKP :: (MultGroup a) => 
                 SubgroupGenerator a -- ^ A generator of a suitable group
              -> Integer             -- ^ The value that you want to proof you
                                     -- know 0 <= x < groupOrder
              -> Integer             -- ^ A cryptographically secure random 
                                     -- number 0 <= v < groupOrder
              -> String              -- ^ Your unique ID as expected by the 
                                     -- verifier
              -> (ByteString -> ByteString) -- ^ A cryptographically secure hash 
                                            -- function
              -> DLZKP a             -- ^ The generated Zero Knowledge Proof
buildDLZKP g x v signer hashFunc =
   let expVal = (generatorValue g) <**> x
       verifier' = (generatorValue g) <**> v
       hin = pack $ show (g, verifier', expVal, signer)
       h = binToInt $ hashFunc hin
       r = v - x*h
   in DLZKP {  generator = g
             , expValue = expVal
             , signerID = signer
             , verifier = verifier'
             , rvalue = r
            }

-- |Verify a Zero Knowledge Proof. This function will verify the supplied
-- proof. However, please be aware that you still have to check the generator
-- value that was used for the proof.
verifyDLZKP :: (MultGroup a) => 
                  (ByteString -> ByteString) -- ^ The cryptographically secure 
                                             -- hash function used for 
                                             -- generating the proof
               -> DLZKP a -- ^ The proof
               -> Bool    -- ^ True iff the proof is valid
verifyDLZKP hashFunc proof =
   let hin = pack $ show $ proofDetails proof
       g = generator proof
       h = binToInt $ hashFunc hin
       rightOrder = ((expValue proof) <**> (subgroupOrder g))
                    == (neutral $ generatorValue g)
       sanity =    (generatorValue g) `sameGroup` (verifier proof)
                && (verifier proof)   `sameGroup` (expValue proof) 
                && rightOrder
   in sanity && 
      verifier proof ==     ((generatorValue g) <**> (rvalue proof)) 
                        <*> ((expValue proof) <**> (h))
   where proofDetails p = (generator p, verifier p, expValue p, signerID p)

-- |Encapsulates all data needed to run the J-PAKE protocol.
data JPAKESecret a = 
   JPAKESecret { 
      secret1 :: Integer -- ^ A cryptographically secure random number 
                         -- 0 <= secret1 < groupOrder
    , secret2 :: Integer -- ^ A cryptographically secure random number 
                         -- 0 < secret2 < groupOrder
    , v1 :: Integer -- ^ A cryptographically secure random number 
                    -- 0 < v1 < groupOrder
    , v2 :: Integer -- ^ A cryptographically secure random number 
                    -- 0 < v2 < groupOrder
    , v3 :: Integer -- ^ A cryptographically secure random number 
                    -- 0 < v3 < groupOrder
    , myName :: String -- ^ Your name as expected by the other party
    , hash :: (ByteString -> ByteString) -- ^ A cryptographically secure 
                                         -- hash function
    , password :: ByteString -- ^ The shared password
    , myGen :: SubgroupGenerator a -- ^ A generator of a suitable subgroup
    , hisName :: String -- ^ The expected name of the other party
   }

-- |The structure used for representing the communication during a J-PAKE
-- protocol run.
data JPAKE a =
     JPAKEStage1 {
         exp1 :: a
       , exp2 :: a
       , proof1 :: DLZKP a
       , proof2 :: DLZKP a
       , gen :: SubgroupGenerator a
     }
   | JPAKEStage2 {
         bigExp :: a
       , proofBigExp :: DLZKP a
       , gen2 :: SubgroupGenerator a
     } deriving (Show, Read)

-- |Compute the first message that needs to be sent in a J-PAKE run.
buildJPAKEStage1 :: (MultGroup a) => 
                    JPAKESecret a -- ^ The secret structure as outlined above
                    -> JPAKE a -- ^ The resulting JPAKE structure
buildJPAKEStage1 s =
   let g = myGen s
       (x1, x2) = ((secret1 s), (secret2 s))
       (v1', v2') = ((v1 s), (v2 s))
       p1 = buildDLZKP g x1 v1' (myName s) (hash s)
       p2 = buildDLZKP g x2 v2' (myName s) (hash s)
       groupOrder = (subgroupOrder g)
   in if (x1 >= 0 && x1 < groupOrder && x2 >= 1 && x2 < groupOrder)
         then JPAKEStage1 { 
                    exp1 = (generatorValue g) <**> x1, 
                    exp2 = (generatorValue g) <**> x2, 
                    proof1 = p1, 
                    proof2 = p2, 
                    gen = g 
                    }
         else error "Illegal JPAKE data."

-- |Verify a peer's first message.
verifyJPAKEStage1 :: (MultGroup a) => 
                     JPAKESecret a -- ^ Our secret structure
                     -> JPAKE a -- ^ The peer's JPAKE message
                     -> Bool -- ^ True iff the peer's message is valid
verifyJPAKEStage1 s (JPAKEStage1 e1 e2 p1 p2 hisG) =
   let hisName' = hisName s
       signerValid = [hisName', hisName'] == map signerID [p1, p2]
       sameGroups  = sameGroup e1 e2
       proofsValid = [True, True] == map (verifyDLZKP (hash s)) [p1, p2]
       proofsMatch = [e1, e2] == map expValue [p1, p2]
       gMatch      = (myGen s) == hisG && hisG == generator p1 && 
                     hisG == generator p2
   in   signerValid && gMatch && e2 /= (neutral e2) && sameGroups && proofsMatch 
     && proofsValid
verifyJPAKEStage1 _ _ = False

-- |Compute the second message that needs to be sent in a J-PAKE run. This
-- function needs to know the peer's first message and will therefore also
-- invoke verifyJPAKEStage1 on it.
buildJPAKEStage2 :: (MultGroup a) => 
                    JPAKESecret a -- ^ Our secret structure
                    -> JPAKE a  -- ^ The peer's first message
                    -> Maybe (JPAKE a) -- ^ Our second message if everything is
                                       -- OK
buildJPAKEStage2 s hisStage1 =
   let g = myGen s
       len = (round $ (logBase 2 (fromIntegral $ subgroupOrder $ g) :: Double)) 
             `div` 8
       gx3 = exp1 hisStage1
       gx4 = exp2 hisStage1
       x1 = secret1 s
       x2 = secret2 s
       -- This will 'shorten' the password hash, but it shouldn't be a problem,
       -- because we're using a sane group.
       s' = binToInt $ Data.ByteString.Lazy.take len $ (hash s) (password s)
       g' = (gx3 <*> gx4 <*> ((generatorValue g) <**> x1))
       myBigExp = g' <**> (x2 * s')
       gen' = SubgroupGenerator { 
                 generatorValue = g'
               , subgroupOrder = subgroupOrder g 
              }
       proof = buildDLZKP gen' (x2 * s') (v3 s) (myName s) (hash s)
       stage2 = JPAKEStage2 {
                   bigExp = myBigExp
                 , proofBigExp = proof
                 , gen2 = gen' 
                }
   in if (verifyJPAKEStage1 s hisStage1) && (s' > 0 && s' < (subgroupOrder g))
         then Just stage2
         else Nothing

-- |Verify a peer's second J-PAKE message.
verifyJPAKEStage2 :: (MultGroup a) => 
                     JPAKESecret a -- ^ Our secret structure
                     -> JPAKE a -- ^ The peer's second J-PAKE message
                     -> Bool -- ^ True iff the verification is OK
verifyJPAKEStage2 s (JPAKEStage2 bigExp' proof g') =
   let hisName' = hisName s
       signerValid = hisName' == signerID proof
       proofValid = verifyDLZKP (hash s) proof
       proofMatches = bigExp' == expValue proof
       gMatch      = g' == generator proof
   in signerValid && gMatch && proofMatches && proofValid
verifyJPAKEStage2 _ _ = False

-- |Derive the shared session key. This function will invoke verifyJPAKEStage2,
-- but not verifyJPAKEStage1.
deriveKey :: (MultGroup a) => 
             JPAKESecret a -- ^ Our secret structure
             -> JPAKE a -- ^ The peer's first J-PAKE message
             -> JPAKE a -- ^ The peer's second J-PAKE message
             -> Maybe ByteString -- ^ The shared session key if everything is OK
deriveKey s (JPAKEStage1 _ gx4 _ _ _) hisStage2 =
   let bigExp' = bigExp hisStage2
       x2 = (secret2 s)
       g = myGen s
       -- This will 'shorten' the password hash, but it shouldn't be a problem,
       -- because we're using a sane group.
       len = (round $ (logBase 2 (fromIntegral $ subgroupOrder $ g) :: Double)) 
             `div` 8
       s' = binToInt $ Data.ByteString.Lazy.take len $ (hash s) (password s )
       ginv = invert $ gx4 <**> (x2 * s')
       k' = (bigExp' <*> ginv) <**> x2
       k  = (hash s) (Bin.encode $ show k')
   in if verifyJPAKEStage2 s hisStage2
         then Just k
         else Nothing
deriveKey _ _ _ = Nothing
