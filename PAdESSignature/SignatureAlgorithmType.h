//
//  SignatureAlgorithmType.h
//  PAdESSignature
//
//  Created by Luis Nicieza on 11/2/25.
//

#ifndef SignatureAlgorithmType_h
#define SignatureAlgorithmType_h

#import <Foundation/Foundation.h>

typedef NSString * SignatureAlgorithmType NS_STRING_ENUM;

FOUNDATION_EXPORT SignatureAlgorithmType const SignatureAlgorithmTypeRSA;
FOUNDATION_EXPORT SignatureAlgorithmType const SignatureAlgorithmTypeEC;

#endif /* SignatureAlgorithmType_h */
