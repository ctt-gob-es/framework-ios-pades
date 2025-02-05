//
//  PresignResponse.m
//  PAdESSignature
//
//  Created by Desarrollo Abamobile on 5/2/25.
//

#import "PresignResponse.h"

@implementation PresignResponse

- (instancetype)initWithData:(nullable NSData *)data error:(nullable NSError *)error {
	self = [super init];
	if (self) {
		_data = data;
		_error = error;
	}
	return self;
}

@end
