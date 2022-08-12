#import "FilecoinPlugin.h"
#if __has_include(<filecoin/filecoin-Swift.h>)
#import <filecoin/filecoin-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "filecoin-Swift.h"
#endif

@implementation FilecoinPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFilecoinPlugin registerWithRegistrar:registrar];
}
@end
