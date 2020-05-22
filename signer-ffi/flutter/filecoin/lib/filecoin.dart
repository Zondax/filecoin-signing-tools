import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'dart:io';

final DynamicLibrary filecoin = Platform.isAndroid
    ? DynamicLibrary.open("libfilecoin_signer_ffi.so")
    : DynamicLibrary.process();

class Filecoin {
  static final Pointer Function() errorNew =
    filecoin
      .lookup<NativeFunction<Pointer Function()>>("filecoin_signer_error_new")
      .asFunction();
  static final int Function(Pointer) errorCode =
    filecoin
      .lookup<NativeFunction<Int32 Function(Pointer)>>("filecoin_signer_error_code")
      .asFunction();
  static final Pointer<Utf8> Function(Pointer) errorMessage =
    filecoin
      .lookup<NativeFunction<Pointer<Utf8> Function(Pointer)>>("filecoin_signer_error_message")
      .asFunction();
  static final void Function(Pointer) errorFree =
    filecoin
      .lookup<NativeFunction<Void Function(Pointer)>>("filecoin_signer_error_free")
      .asFunction();

  static final Pointer<Utf8> Function(Pointer) extendedKeyPrivateKey =
    filecoin
      .lookup<NativeFunction<Pointer<Utf8> Function(Pointer)>>("filecoin_signer_extended_key_private_key")
      .asFunction();
  static final Pointer<Utf8> Function(Pointer) extendedKeyPublicKey =
    filecoin
      .lookup<NativeFunction<Pointer<Utf8> Function(Pointer)>>("filecoin_signer_extended_key_public_key")
      .asFunction();
  static final void Function(Pointer) extendedKeyFree =
    filecoin
      .lookup<NativeFunction<Void Function(Pointer)>>("filecoin_signer_extended_key_free")
      .asFunction();

  static final Pointer Function(Pointer<Utf8>, Pointer<Utf8>, Pointer) keyDerive =
    filecoin
      .lookup<NativeFunction<Pointer Function(Pointer<Utf8>, Pointer<Utf8>, Pointer)>>("filecoin_signer_key_derive")
      .asFunction();

  static final void Function(Pointer<Utf8>) stringFree =
    filecoin
      .lookup<NativeFunction<Void Function(Pointer<Utf8>)>>("filecoin_signer_string_free")
      .asFunction();
}

