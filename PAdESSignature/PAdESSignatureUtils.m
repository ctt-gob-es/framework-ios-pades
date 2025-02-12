//
//  PAdESSignatureUtils.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 10/12/24.
//

#import "PAdESSignatureUtils.h"

#import <Foundation/Foundation.h>
#import "PadesSignerWrapper.h"

//JAVA J2OBJC FILES
#import "IOSObjectArray.h"
#import "J2ObjC_source.h"
#import "IOSPrimitiveArray.h"
#import "Keyloader.h"
#import "SignatureResult.h"
#import "PresignResult.h"
#import "PdfSignResult.h"

#include "java/util/Properties.h"
#include "java/security/KeyFactory.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/security/cert/CertificateFactory.h"
#include "java/security/cert/Certificate.h"
#include "java/security/PrivateKey.h"
#include "SignatureAlgorithmType.h"


@implementation PAdESSignatureUtils

typedef void (^SignPdfCompletionHandler)(NSString * result, NSError * error);

- (void)signPdfWithData:(NSData *)pdfData
      hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType
			 privateKey:(SecKeyRef)privateKey
			certificate:(SecCertificateRef)certificate
			extraParams:(NSDictionary *)extraParams
			 completion:(SignPdfCompletionHandler)completion {
	
    SignatureAlgorithmType certificateAlgorithm = [self getCertificateAlgorithm:certificate];
    NSString *signAlgorithm = [self getSignAlgorithm:hashAlgorithmType withSignatureAlgorithmType:certificateAlgorithm];
    
	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	id<JavaSecurityPrivateKey> pvt = [self obtainPrivateKey:privateKey withNSString:certificateAlgorithm];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];
	
	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];
	
	//We don´t know the sign algorithm to use so we pass nil
	EsGobAfirmaIosSignatureResult *result = [signerWrapper signWithByteArray:iosPdfData
																withNSString:signAlgorithm
												  withJavaSecurityPrivateKey:pvt
										withJavaSecurityCertCertificateArray:certChainArray
													  withJavaUtilProperties:javaProperties];
	
	if(result.getErrorCode == -1) {
		IOSByteArray *byteArray = [result getSignature];
		NSString *base64String = [self convertIOSByteArrayToBase64String:byteArray];
		completion(base64String, nil);
	} else {
		NSInteger errorCode = [result getErrorCode];
		NSError *error = [NSError errorWithDomain:@"Error Signing PDF"
											 code:errorCode
										 userInfo:@{NSLocalizedDescriptionKey: @"Signing failed"}];
		completion(nil, error);
	}
}

EsGobAfirmaIosPresignResult* testPresignResult;

- (PresignResponse *)dniePresignPdfWithData:(NSData *)pdfData
                          hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType
								certificate:(SecCertificateRef)certificate
							   extraParams:(NSDictionary *)extraParams {

    SignatureAlgorithmType certificateAlgorithm = [self getCertificateAlgorithm:certificate];
    NSString *signAlgorithm = [self getSignAlgorithm:hashAlgorithmType withSignatureAlgorithmType:certificateAlgorithm];
    
	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];

	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];
	EsGobAfirmaIosPresignResult *presignResult = [signerWrapper presignWithByteArray:iosPdfData withNSString:signAlgorithm withJavaSecurityCertCertificateArray:certChainArray withJavaUtilProperties:javaProperties];

	if (!presignResult || presignResult.getErrorCode != -1) {
		NSInteger errorCode = presignResult ? presignResult.getErrorCode : -9999;
		NSError *error = [NSError errorWithDomain:@"DNIePresignError"
											 code:errorCode
										 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"DNIe presign failed with error code %ld", (long)errorCode]}];
		return [[PresignResponse alloc] initWithData:nil error:error retry:presignResult.canRetry];
	}

	testPresignResult = presignResult;
	NSData *presignDataResult = [[[presignResult getPreSignature] getSign] toNSData];
	
	return [[PresignResponse alloc] initWithData:presignDataResult error:nil retry:false];
}

- (PostsignResponse *)dniePostsignPdfWithData:(NSData *)pdfData
                            hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType
								  certificate:(SecCertificateRef)certificate
								 extraParams:(NSDictionary *)extraParams
									   pkcs1:(NSData *)pkcs1 {
    
    SignatureAlgorithmType certificateAlgorithm = [self getCertificateAlgorithm:certificate];
    NSString *signAlgorithm = [self getSignAlgorithm:hashAlgorithmType withSignatureAlgorithmType:certificateAlgorithm];
    
    if (!testPresignResult) {
		NSError *error = [NSError errorWithDomain:@"DNIePostsignError"
											 code:-2
										 userInfo:@{NSLocalizedDescriptionKey: @"Postsign failed: No valid presign result available"}];
		return [[PostsignResponse alloc] initWithSignedString:nil error:error retry:testPresignResult.canRetry];
	}

	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];

	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];

	IOSByteArray *convertedPKCS1 = [self dataToIOSByteArray:pkcs1];
	EsGobAfirmaIosSignatureResult *postsignResult = [signerWrapper postsignWithByteArray:iosPdfData withEsGobAfirmaIosPresignResult:testPresignResult withByteArray:convertedPKCS1 withNSString:signAlgorithm withJavaSecurityCertCertificateArray:certChainArray withJavaUtilProperties:javaProperties];

	if (!postsignResult || postsignResult.getErrorCode != -1) {
		NSInteger errorCode = postsignResult ? postsignResult.getErrorCode : -9999;
		NSError *error = [NSError errorWithDomain:@"DNIePostsignError"
											 code:errorCode
										 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"DNIe postsign failed with error code %ld", (long)errorCode]}];
		return [[PostsignResponse alloc] initWithSignedString:nil error:error retry:false];
	}

	IOSByteArray *byteArray = [postsignResult getSignature];
	NSString *base64String = [self convertIOSByteArrayToBase64String:byteArray];

	return [[PostsignResponse alloc] initWithSignedString:base64String error:nil retry:false];
}

- (IOSByteArray *)dataToIOSByteArray:(NSData *)data {
	return [IOSByteArray arrayWithBytes:[data bytes] count:[data length]];
}

- (id<JavaSecurityPrivateKey>)obtainPrivateKey:(SecKeyRef)privateKey withNSString:(NSString *)algorithm {
	CFDictionaryRef attributes = SecKeyCopyAttributes(privateKey);
	NSData *privateKeyNSData = CFDictionaryGetValue(attributes, kSecValueData);
	IOSByteArray *privateKeyData = [IOSByteArray arrayWithBytes:[privateKeyNSData bytes] count:[privateKeyNSData length]];
	JavaIoByteArrayInputStream *inputStream = [[JavaIoByteArrayInputStream alloc] initWithByteArray:privateKeyData];
	id<JavaSecurityPrivateKey> pvt = [EsGobAfirmaIosKeyLoader loadPrivateKeyWithJavaIoInputStream:inputStream withNSString: algorithm];
	
	if (attributes) {
		CFRelease(attributes);
	}
	return pvt;
}

- (IOSObjectArray *)obtainCertificateChain:(SecCertificateRef)certificate {
	CFDataRef certData = SecCertificateCopyData(certificate);
	NSData *certNSData = (__bridge NSData *)certData;
	IOSByteArray *certificateData = [IOSByteArray arrayWithBytes:[certNSData bytes] count:[certNSData length]];
	JavaIoByteArrayInputStream *inputStream = [[JavaIoByteArrayInputStream alloc] initWithByteArray:certificateData];
	JavaSecurityCertCertificateFactory *cf = JavaSecurityCertCertificateFactory_getInstanceWithNSString_(@"X.509");
	JavaSecurityCertCertificate *certChain = [cf generateCertificateWithJavaIoInputStream:inputStream];
	IOSObjectArray *certChainArray = [IOSObjectArray arrayWithLength:1 type:JavaSecurityCertCertificate_class_()];
	[certChainArray replaceObjectAtIndex:0 withObject:certChain];
	
	if (certData) {
		CFRelease(certData);
	}
	return certChainArray;
}

- (JavaUtilProperties *)obtainExtraParams:(NSDictionary *)extraParams {
	JavaUtilProperties *javaProperties = [[JavaUtilProperties alloc] init];
	for (NSString *key in extraParams) {
		[javaProperties setPropertyWithNSString:key withNSString:[extraParams objectForKey:key]];
	}
	return javaProperties;
}

- (NSString *)convertIOSByteArrayToBase64String:(IOSByteArray *)byteArray {
	NSData *data = [NSData dataWithBytes:byteArray->buffer_ length:byteArray->size_];
	NSString *base64String = [data base64EncodedStringWithOptions:0];
	return base64String;
}

- (NSString *) getSignAlgorithm:(HashAlgorithmType) hashAlgorithmType withSignatureAlgorithmType:(SignatureAlgorithmType) signatureAlgorithmType {
    
    NSString *prefix = HashAlgorithmTypeSHA256;
    if (hashAlgorithmType != nil) {
        prefix = hashAlgorithmType;
    }
    
    NSString *suffix = @"withRSA";
    if (signatureAlgorithmType != nil && [signatureAlgorithmType isEqualToString: SignatureAlgorithmTypeRSA]) {
        suffix = @"withRSA";
    } else if (signatureAlgorithmType != nil && [signatureAlgorithmType isEqualToString: SignatureAlgorithmTypeEC]) {
        suffix = @"withECDSA";
    }
    
    return [NSString stringWithFormat:@"%@%@", prefix, suffix];
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

- (NSString *) getSignAlgorithm:(HashAlgorithmType)hashAlgorithmType
                withCertificate:(SecCertificateRef)certificate {
    SignatureAlgorithmType certificateAlgorithm = [self getCertificateAlgorithm:certificate];
    return [self getSignAlgorithm:hashAlgorithmType withSignatureAlgorithmType:certificateAlgorithm];
    
}

@end
