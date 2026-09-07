// Intentionally insecure iOS source, used as an analyzer test fixture.
// Compiled for arm64-apple-ios so the analyzer is exercised against a genuine
// iOS Mach-O rather than hand-written bytes.
#import <Foundation/Foundation.h>

static NSString *const kAWSAccessKey   = @"AKIA7QW3ZXNM2PLKD8VR";
static NSString *const kStripeKey      = @"sk_live_4eC39HqLyjWDarjtT1zdp7dcVXYZab12";
static NSString *const kGitHubToken    = @"ghp_9Zx8Yw7Vu6Ts5Rq4Pn3Mm2Ll1Kk0JjIiHhGg";
static NSString *const kAdminPassword  = @"ios-admin-p4ssw0rd-do-not-ship";
static NSString *const kAPIBase        = @"http://api.insecure-ios-demo.example.com/v1";
static NSString *const kTelemetry      = @"http://telemetry.insecure-ios-demo.example.com/e";
static NSString *const kHardcodedKey   = @"0123456789abcdef0123456789abcdef";

@interface DemoCredentialStore : NSObject
- (void)persistToken:(NSString *)token;
- (NSString *)loadToken;
@end

@implementation DemoCredentialStore

- (void)persistToken:(NSString *)token {
    // Credentials written to an unencrypted plist that is included in backups.
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:token forKey:@"auth_token"];
    [defaults setObject:kAdminPassword forKey:@"user_password"];
    [defaults setObject:kAWSAccessKey forKey:@"aws_access_key"];
    [defaults synchronize];

    // Keychain item readable while the device is locked.
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount: @"session",
        (__bridge id)kSecAttrAccessible: @"kSecAttrAccessibleAlways",
        (__bridge id)kSecValueData: [token dataUsingEncoding:NSUTF8StringEncoding],
    };
    NSLog(@"storing keychain item %@", query);
}

- (NSString *)loadToken {
    return [[NSUserDefaults standardUserDefaults] stringForKey:@"auth_token"];
}

@end

@interface DemoNetworkClient : NSObject
- (void)fetchProfile;
@end

@implementation DemoNetworkClient

- (void)fetchProfile {
    NSURL *url = [NSURL URLWithString:kAPIBase];
    NSLog(@"requesting %@ with password %@", url, kAdminPassword);
    NSLog(@"telemetry endpoint %@ token %@", kTelemetry, kGitHubToken);
}

@end

@interface DemoCryptoHelper : NSObject
- (NSString *)weakHashOfPassword:(NSString *)password;
@end

@implementation DemoCryptoHelper

- (NSString *)weakHashOfPassword:(NSString *)password {
    // Broken primitives referenced by name so the string pool carries them.
    NSArray *algorithms = @[@"MD5", @"SHA-1", @"DES", @"RC4", @"AES/ECB/PKCS5Padding"];
    NSLog(@"hashing with %@ key %@ stripe %@", algorithms, kHardcodedKey, kStripeKey);
    return [algorithms componentsJoinedByString:@","];
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        DemoCredentialStore *store = [[DemoCredentialStore alloc] init];
        [store persistToken:@"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpb3MifQ.abcdEFGH1234"];
        [[DemoNetworkClient alloc] init];
        [[DemoCryptoHelper alloc] init];
    }
    return 0;
}
