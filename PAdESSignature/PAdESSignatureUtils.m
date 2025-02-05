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

@implementation PAdESSignatureUtils

typedef void (^SignPdfCompletionHandler)(NSString * result, NSError * error);

/*- (instancetype)initWithDelegate:(id<PadesManagerDelegate>)delegate {
	self = [super init];
	if (self) {
		_delegate = delegate; // Assign delegate
	}
	return self;
}*/

- (void)signPdfWithData:(NSData *)pdfData
		  signAlgorithm:(NSString *)signAlgorithm
			 privateKey:(SecKeyRef)privateKey
			certificate:(SecCertificateRef)certificate
   certificateAlgorithm:(NSString *)certificateAlgorithm
			extraParams:(NSDictionary *)extraParams
			 completion:(SignPdfCompletionHandler)completion {
	
	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	JavaSecurityPrivateKey *pvt = [self obtainPrivateKey:privateKey withNSString:certificateAlgorithm];
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
		printf("Signature generated in device : %s\n", [base64String UTF8String]);
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
							  signAlgorithm:(NSString *)signAlgorithm
								certificate:(SecCertificateRef)certificate
					   certificateAlgorithm:(NSString *)certificateAlgorithm
							   extraParams:(NSDictionary *)extraParams {

	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];

	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];
	EsGobAfirmaIosPresignResult *presignResult = [signerWrapper presignWithByteArray:iosPdfData
																	   withNSString:signAlgorithm
											   withJavaSecurityCertCertificateArray:certChainArray
															 withJavaUtilProperties:javaProperties];

	if (!presignResult || presignResult.getErrorCode != -1) {
		NSInteger errorCode = presignResult ? presignResult.getErrorCode : -9999;
		NSError *error = [NSError errorWithDomain:@"DNIePresignError"
											 code:errorCode
										 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"DNIe presign failed with error code %ld", (long)errorCode]}];
		NSLog(@"DNIe presign failed: %@", error.localizedDescription);
		return [[PresignResponse alloc] initWithData:nil error:error];
	}

	testPresignResult = presignResult;

	NSData *presignDataResult = [[[presignResult getPreSignature] getSign] toNSData];
	NSLog(@"DNIe presign successful");

	return [[PresignResponse alloc] initWithData:presignDataResult error:nil];
}

- (PostsignResponse *)dniePostsignPdfWithData:(NSData *)pdfData
								signAlgorithm:(NSString *)signAlgorithm
								  certificate:(SecCertificateRef)certificate
						 certificateAlgorithm:(NSString *)certificateAlgorithm
								 extraParams:(NSDictionary *)extraParams
									   pkcs1:(NSData *)pkcs1 {
	if (!testPresignResult) {
		NSError *error = [NSError errorWithDomain:@"DNIePostsignError"
											 code:-2
										 userInfo:@{NSLocalizedDescriptionKey: @"Postsign failed: No valid presign result available"}];
		NSLog(@"DNIe postsign error: %@", error.localizedDescription);
		return [[PostsignResponse alloc] initWithSignedString:nil error:error];
	}

	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];

	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];

	IOSByteArray *convertedPKCS1 = [self dataToIOSByteArray:pkcs1];
	EsGobAfirmaIosSignatureResult *postsignResult = [signerWrapper postsignWithByteArray:iosPdfData
													 withEsGobAfirmaIosPresignResult:testPresignResult
																	   withByteArray:convertedPKCS1
																		withNSString:signAlgorithm
											  withJavaSecurityCertCertificateArray:certChainArray
															withJavaUtilProperties:javaProperties];

	if (!postsignResult || postsignResult.getErrorCode != -1) {
		NSInteger errorCode = postsignResult ? postsignResult.getErrorCode : -9999;
		NSError *error = [NSError errorWithDomain:@"DNIePostsignError"
											 code:errorCode
										 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"DNIe postsign failed with error code %ld", (long)errorCode]}];
		NSLog(@"DNIe postsign error: %@", error.localizedDescription);
		return [[PostsignResponse alloc] initWithSignedString:nil error:error];
	}

	IOSByteArray *byteArray = [postsignResult getSignature];
	NSString *base64String = [self convertIOSByteArrayToBase64String:byteArray];

	return [[PostsignResponse alloc] initWithSignedString:base64String error:nil];
}


/*- (void)dnieSignPdfWithData:(NSData *)pdfData
			  signAlgorithm:(NSString *)signAlgorithm
				 privateKey:(SecKeyRef)privateKey
				certificate:(SecCertificateRef)certificate
	   certificateAlgorithm:(NSString *)certificateAlgorithm
				extraParams:(NSDictionary *)extraParams
				 completion:(SignPdfCompletionHandler)completion {
	IOSByteArray *iosPdfData = [self dataToIOSByteArray:pdfData];
	JavaSecurityPrivateKey *pvt = [self obtainPrivateKey:privateKey withNSString:certificateAlgorithm];
	IOSObjectArray *certChainArray = [self obtainCertificateChain:certificate];
	JavaUtilProperties *javaProperties = [self obtainExtraParams:extraParams];
	EsGobAfirmaIosPadesSignerWrapper *signerWrapper = [[EsGobAfirmaIosPadesSignerWrapper alloc] init];
	EsGobAfirmaIosPresignResult *presignResult = [signerWrapper presignWithByteArray:iosPdfData
																   withNSString:signAlgorithm
										   withJavaSecurityCertCertificateArray:certChainArray
														 withJavaUtilProperties:javaProperties];
	
	if(presignResult.getErrorCode == -1) {
		if (self.delegate) {
			NSData *presignDataResult = [[[presignResult getPreSignature] getSign] toNSData];
			[self.delegate generatePKCS1WithPreSignResult: presignDataResult completion:^(NSData *pkcs1) {
				IOSByteArray *convertedPKCS1 = [self dataToIOSByteArray:pkcs1];
				EsGobAfirmaIosSignatureResult *result = [signerWrapper postsignWithByteArray:iosPdfData
															 withEsGobAfirmaIosPresignResult:presignResult
																			   withByteArray:convertedPKCS1
																				withNSString:signAlgorithm
														withJavaSecurityCertCertificateArray:certChainArray
																	  withJavaUtilProperties:javaProperties];
				
				if(result.getErrorCode == -1) {
					IOSByteArray *byteArray = [result getSignature];
					NSString *base64String = [self convertIOSByteArrayToBase64String:byteArray];
					printf("Signature generated in device : %s\n", [base64String UTF8String]);
					completion(base64String, nil);
				} else {
					NSInteger errorCode = [result getErrorCode];
					NSError *error = [NSError errorWithDomain:@"Error Signing PDF"
														 code:errorCode
													 userInfo:@{NSLocalizedDescriptionKey: @"Signing failed"}];
					completion(nil, error);
				}
			}];
		}
	} else {
		NSInteger errorCode = [presignResult getErrorCode];
		NSError *error = [NSError errorWithDomain:@"Error Signing PDF"
											 code:errorCode
										 userInfo:@{NSLocalizedDescriptionKey: @"Signing failed"}];
		completion(nil, error);
	}
}*/

- (IOSByteArray *)dataToIOSByteArray:(NSData *)data {
	return [IOSByteArray arrayWithBytes:[data bytes] count:[data length]];
}

- (JavaSecurityPrivateKey *)obtainPrivateKey:(SecKeyRef)privateKey withNSString:(NSString *)algorithm {
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

@end
