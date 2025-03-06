//
//  CertificateUtils.h
//  PAdESSignature
//
//  Created by Luis Nicieza on 5/3/25.
//

#ifndef CertificateService_h
#define CertificateService_h

#import <Foundation/Foundation.h>
#import "HashAlgorithmType.h"
#import "SignatureAlgorithmType.h"

@interface CertificateService : NSObject

- (SecKeyAlgorithm)getAlgorithmByCertificate:(SecKeyRef)privateKey hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType;
    
- (SignatureAlgorithmType)getCertificateAlgorithm:(SecCertificateRef) certificate;
    
@end


#endif /* CertificateService */
