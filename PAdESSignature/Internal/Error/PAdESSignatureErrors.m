//
//  PAdESSignatureErrors.m
//  PAdESSignature
//
//  Created by Luis Nicieza on 5/3/25.
//

#import "PAdESSignatureErrors.h"

typedef NS_ENUM(NSInteger, PAdESSignatureErrorCode) {
    PAdESSignatureErrorPresignError = 1001,
    PAdESSignatureErrorSignAlgorithmError = 1002,
    PAdESSignatureErrorInvalidSignature = 1003,
    PAdESSignatureErrorPresignNotFoundError = 1004,
    PAdESSignatureErrorPostSignError = 1005
};

@implementation PAdESSignatureErrors

+ (NSError *)presignError {
    return [NSError errorWithDomain:PAdESSignatureErrorDomain
                               code:PAdESSignatureErrorPresignError
                           userInfo:@{NSLocalizedDescriptionKey: @"Presign error occurred"}];
}

+ (NSError *)invalidSignAlgorithm {
    return [NSError errorWithDomain:PAdESSignatureErrorDomain
                               code:PAdESSignatureErrorSignAlgorithmError
                           userInfo:@{NSLocalizedDescriptionKey: @"Invalid signature"}];
}

+ (NSError *)invalidSignatureError {
    return [NSError errorWithDomain:PAdESSignatureErrorDomain
                               code:PAdESSignatureErrorInvalidSignature
                           userInfo:@{NSLocalizedDescriptionKey: @"Invalid signature"}];
}

+ (NSError *)presignNotFound {
    return [NSError errorWithDomain:PAdESSignatureErrorDomain
                               code:PAdESSignatureErrorPresignNotFoundError
                           userInfo:@{NSLocalizedDescriptionKey: @"Missing certificate"}];
}

+ (NSError *)postSignError {
    return [NSError errorWithDomain:PAdESSignatureErrorDomain
                               code:PAdESSignatureErrorPostSignError
                           userInfo:@{NSLocalizedDescriptionKey: @"Unknown error"}];
}

@end
