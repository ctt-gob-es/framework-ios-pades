//
//  CertificateUtils.m
//  PAdESSignature
//
//  Created by Luis Nicieza on 5/3/25.
//

#import "CertificateService.h"

@implementation CertificateService

- (SecKeyAlgorithm)getAlgorithmByCertificate:(SecKeyRef)privateKey hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType {
    if ([self isCertificateRSA:privateKey]) {
        // Es Certificado RSA
        if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA1]) {
            return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
        }
        else if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA256]) {
            return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
        }
        else if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA384]) {
            return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
        }
        else if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA512]) {
            return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
        }
        else{
            return NULL;
        }
    } else if ([self isCertificateECDSA:privateKey]){
        // Es certificado ECDSA
        if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA1]) {
            return kSecKeyAlgorithmECDSASignatureMessageX962SHA1;
        }
        else if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA256]) {
            return kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
        }
        else if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA384]) {
            return kSecKeyAlgorithmECDSASignatureMessageX962SHA384;
        }
        else if ([hashAlgorithmType isEqualToString:HashAlgorithmTypeSHA512]) {
            return kSecKeyAlgorithmECDSASignatureMessageX962SHA512;
        }
        else{
            return NULL;
        }
    }
    return  NULL;
}

- (BOOL) isCertificateECDSA:(SecKeyRef)privateKey {
    return [self isCertificateKeyType:privateKey keyType:kSecAttrKeyTypeECSECPrimeRandom];
}

- (BOOL) isCertificateRSA:(SecKeyRef)privateKey {
    return [self isCertificateKeyType:privateKey keyType:kSecAttrKeyTypeRSA];
}

- (BOOL) isCertificateKeyType:(SecKeyRef)privateKey keyType:(CFStringRef) keSecAttrKeyType{
    
    CFDictionaryRef attributes = SecKeyCopyAttributes(privateKey);
    if (!attributes) {
        return nil;
    }
    
    NSString *keyType = ( NSString *)CFDictionaryGetValue(attributes, kSecAttrKeyType);
    CFRelease(attributes);
    
    if (!keyType) {
        NSLog(@"No se pudo determinar el tipo de clave.");
        return nil;
    }
    
    
    if ([keyType isEqualToString:(__bridge NSString *)keSecAttrKeyType]) {
        return YES;
    }
    
    return NO;
}

- (SignatureAlgorithmType)getCertificateAlgorithm:(SecCertificateRef) certificate {
    if (!certificate) {
        NSLog(@"Invalid certificate reference");
        return nil;
    }

    CFDataRef certificateData = SecCertificateCopyData(certificate);
    if (!certificateData) {
        NSLog(@"Unable to extract certificate data");
        return nil;
    }

    SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, certificateData);
    CFRelease(certificateData);
    
    if (!certificateRef) {
        NSLog(@"Unable to create certificate reference");
        return nil;
    }

    SecKeyRef publicKey = SecCertificateCopyKey(certificateRef);
    CFRelease(certificateRef);
    
    if (!publicKey) {
        NSLog(@"Unable to extract public key from certificate");
        return nil;
    }

    CFDictionaryRef keyAttributes = SecKeyCopyAttributes(publicKey);
    CFRelease(publicKey);

    if (!keyAttributes) {
        NSLog(@"Unable to extract key attributes");
        return nil;
    }

    CFStringRef keyType = CFDictionaryGetValue(keyAttributes, kSecAttrKeyType);
    CFRelease(keyAttributes);

    if (keyType) {
        if (CFStringCompare(keyType, kSecAttrKeyTypeRSA, 0) == kCFCompareEqualTo) {
            return SignatureAlgorithmTypeRSA;
        } else if (CFStringCompare(keyType, kSecAttrKeyTypeEC, 0) == kCFCompareEqualTo) {
            return SignatureAlgorithmTypeEC;
        } else {
            return nil;
        }
    }

    return nil;
}

@end
