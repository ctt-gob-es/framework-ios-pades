//
//  PostsignResponse.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 5/2/25.
//

#import "PostsignResponse.h"

@implementation PostsignResponse

- (instancetype)initWithSignedString:(nullable NSString *)signedString error:(nullable NSError *)error {
	self = [super init];
	if (self) {
		_signedString = signedString;
		_error = error;
	}
	return self;
}

@end
