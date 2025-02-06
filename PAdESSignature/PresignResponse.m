//
//  PresignResponse.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 5/2/25.
//

#import "PresignResponse.h"

@implementation PresignResponse

- (instancetype)initWithData:(nullable NSData *)data
					   error:(nullable NSError *)error
					   retry:(BOOL)retry {
	self = [super init];
	if (self) {
		_data = data;
		_error = error;
		_retry = retry;
	}
	return self;
}

@end
