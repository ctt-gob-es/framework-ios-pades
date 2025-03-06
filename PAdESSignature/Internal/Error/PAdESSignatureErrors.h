//
//  PAdESSignatureErrors.h
//  PAdESSignature
//
//  Created by Luis Nicieza on 5/3/25.
//

#ifndef PAdESSignatureErrors_h
#define PAdESSignatureErrors_h

#import <Foundation/Foundation.h>

NSString *const PAdESSignatureErrorDomain = @"PAdESSignature";

// Métodos para crear errores
@interface PAdESSignatureErrors : NSObject

+ (NSError *)presignError;
+ (NSError *)invalidSignAlgorithm;
+ (NSError *)invalidSignatureError;
+ (NSError *)presignNotFound;
+ (NSError *)postSignError;
    
@end

#endif /* PAdESSignatureErrors_h */
