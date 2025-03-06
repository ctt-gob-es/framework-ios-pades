//
//  PAdESSignatureUtils.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 10/12/24.
//

#import "PAdESSigner.h"

#import "CertificateService.h"
#import "SignatureAlgorithmType.h"
#import "PAdESSignatureErrors.h"

//JAVA J2OBJC FILES
#import "PadesSignerWrapper.h"
#import "IOSObjectArray.h"
#import "J2ObjC_source.h"
#import "IOSPrimitiveArray.h"
#import "SignatureResult.h"
#import "PdfSignResult.h"
#import "PresignResult.h"

#include "java/util/Properties.h"
#include "java/security/KeyFactory.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/security/cert/CertificateFactory.h"
#include "java/security/cert/Certificate.h"
#include "java/security/PrivateKey.h"


@implementation PAdESSigner

EsGobAfirmaIosPresignResult *dataPresignResult;

- (SignResponse *)signPdfWithData:(NSData *)pdfData
      hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType
             privateKey:(SecKeyRef)privateKey
			certificate:(SecCertificateRef)certificate
            extraParams:(NSDictionary *)extraParams {
	
    PresignResponse *presignResponse = [self presignPdfWithData:pdfData hashAlgorithmType:hashAlgorithmType certificate:certificate extraParams:extraParams];
    
    if (presignResponse.error != nil) {
        return [[SignResponse alloc] initWithSignedString:nil error:presignResponse.error retry:presignResponse.retry];
    }
    
    NSError *error = nil;
    NSData *dataSign = [self signDataWithPrivateKey:&privateKey data:presignResponse.data hashAlgorithmType:hashAlgorithmType error: &error];
    
    if (error != nil) {
        // Error al hacer la firma
        return [[SignResponse alloc] initWithSignedString:nil error:presignResponse.error retry:presignResponse.retry];
    }
    
    SignResponse *signResponse = [self postsignPdfWithData:pdfData hashAlgorithmType:hashAlgorithmType certificate:certificate extraParams:extraParams pkcs1:dataSign];
    
    return signResponse;
}

- (PresignResponse *)presignPdfWithData:(NSData *)pdfData
                          hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType
								certificate:(SecCertificateRef)certificate
							   extraParams:(NSDictionary *)extraParams {

    dataPresignResult = nil;
    
    NSString *signAlgorithm = [self getSignAlgorithm:hashAlgorithmType withCertificate:certificate];
                               
	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];

	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];
	EsGobAfirmaIosPresignResult *presignResult = [signerWrapper presignWithByteArray:iosPdfData withNSString:signAlgorithm withJavaSecurityCertCertificateArray:certChainArray withJavaUtilProperties:javaProperties];

	if (!presignResult || presignResult.getErrorCode != -1) {
        NSError *error;
        if (presignResult) {
            error = [NSError errorWithDomain:PAdESSignatureErrorDomain
                                                 code:presignResult.getErrorCode
                                             userInfo:@{NSLocalizedDescriptionKey: presignResult.getErrorMessage}];
        } else {
            error = [PAdESSignatureErrors presignError];
        }
        
        return [[PresignResponse alloc] initWithData:nil error:error retry:presignResult ? presignResult.canRetry : false];
	}

    dataPresignResult = presignResult;
	NSData *presignDataResult = [[[presignResult getPreSignature] getSign] toNSData];
	
	return [[PresignResponse alloc] initWithData:presignDataResult error:nil retry:false];
}

- (SignResponse *)postsignPdfWithData:(NSData *)pdfData
                            hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType
								  certificate:(SecCertificateRef)certificate
								 extraParams:(NSDictionary *)extraParams
									   pkcs1:(NSData *)pkcs1 {
    
    NSString *signAlgorithm = [self getSignAlgorithm:hashAlgorithmType withCertificate:certificate];
    
    if (!dataPresignResult) {
        NSError *error = [PAdESSignatureErrors presignNotFound];
		return [[SignResponse alloc] initWithSignedString:nil error:error retry:false];
	}

	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];

	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];

	IOSByteArray *convertedPKCS1 = [self dataToIOSByteArray:pkcs1];
	EsGobAfirmaIosSignatureResult *postsignResult = [signerWrapper postsignWithByteArray:iosPdfData withEsGobAfirmaIosPresignResult:dataPresignResult withByteArray:convertedPKCS1 withNSString:signAlgorithm withJavaSecurityCertCertificateArray:certChainArray withJavaUtilProperties:javaProperties];

	if (!postsignResult || postsignResult.getErrorCode != -1) {
        
        NSError *error;
        if (postsignResult) {
            error = [NSError errorWithDomain:PAdESSignatureErrorDomain
                                                 code:postsignResult.getErrorCode
                                             userInfo:@{NSLocalizedDescriptionKey: postsignResult.getErrorMessage}];
        } else {
            error = [PAdESSignatureErrors postSignError];
        }
        
        return [[SignResponse alloc] initWithSignedString:nil error:error retry: false];
	}

	IOSByteArray *byteArray = [postsignResult getSignature];
	NSString *base64String = [self convertIOSByteArrayToBase64String:byteArray];

	return [[SignResponse alloc] initWithSignedString:base64String error:nil retry:false];
}

- (NSString *) getSignAlgorithm:(HashAlgorithmType)hashAlgorithmType
                withCertificate:(SecCertificateRef)certificate {
    SignatureAlgorithmType certificateAlgorithm = [[CertificateService alloc] getCertificateAlgorithm:certificate];
    
    return [self getSignAlgorithm:hashAlgorithmType withSignatureAlgorithmType:certificateAlgorithm];
}


- (NSString *) getSignAlgorithm:(HashAlgorithmType) hashAlgorithmType withSignatureAlgorithmType:(SignatureAlgorithmType) signatureAlgorithmType {
    
    // Por defecto establecemos SHA256. Si no sllega otro por parametro lo establecemos
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


- (NSData *)signDataWithPrivateKey:(SecKeyRef *)privateKey data:(NSData *)data hashAlgorithmType:(HashAlgorithmType)hashAlgorithmType error:(NSError **) error{
    CFErrorRef errorRef = NULL;
    SecKeyAlgorithm secKeyAlgorithm = [[CertificateService alloc] getAlgorithmByCertificate:*privateKey hashAlgorithmType:hashAlgorithmType];
    
    if (secKeyAlgorithm == nil) {
        *error = [PAdESSignatureErrors invalidSignAlgorithm];
    }
    
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(*privateKey,
                                                            secKeyAlgorithm,
                                                            (__bridge CFDataRef)data,
                                                            &errorRef);
    if (!signature) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"Error al firmar los datos: %@", err);
        
        *error = [PAdESSignatureErrors invalidSignatureError];
    } else {
        NSLog(@"Éxito al firmar los datos con el algoritmo: %@", secKeyAlgorithm);
    }
    
    return signature;
}



- (IOSByteArray *)dataToIOSByteArray:(NSData *)data {
	return [IOSByteArray arrayWithBytes:[data bytes] count:[data length]];
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



@end
