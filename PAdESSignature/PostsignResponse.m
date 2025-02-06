//
//  PostsignResponse.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 5/2/25.
//

#import "PostsignResponse.h"

@implementation PostsignResponse

- (instancetype)initWithSignedString:(nullable NSString *)signedString
							   error:(nullable NSError *)error
							   retry:(BOOL)retry {
	self = [super init];
	if (self) {
		_signedString = [signedString copy];
		_error = error;
		_retry = retry;
	}
	return self;
}

@end
