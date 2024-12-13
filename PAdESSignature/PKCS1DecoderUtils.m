//
//  PKCS1DecoderUtils.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 13/12/24.
//

#import "PKCS1DecoderUtils.h"

#import <Foundation/Foundation.h>

//JAVA J2OBJC FILES
#import "IOSObjectArray.h"
#import "J2ObjC_source.h"
#import "IOSPrimitiveArray.h"
#import "Pkcs1Utils.h"

@implementation PKCS1DecoderUtils

+ (IOSByteArray *)decodeSignatureWithByteArray:(IOSByteArray *)signature {
	return EsGobAfirmaCoreSignersPkcs1Utils_decodeSignatureWithByteArray_(signature);
}

@end
