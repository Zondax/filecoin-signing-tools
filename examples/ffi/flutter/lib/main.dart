import 'dart:io';
import 'package:flutter/material.dart';
import 'package:filecoin/filecoin.dart';
import 'dart:ffi';
import 'package:ffi/ffi.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  static const String Mnemonic = 'equip will roof matter pink blind book anxiety banner elbow sun young';
  static const String Path = "m/44'/461'/0/0/0";
  static const String LanguageCode = "en";

  static String _privateKey() {
    var error = Filecoin.errorNew();
    var extendedKey = Filecoin.keyDerive(Utf8.toUtf8(Mnemonic), Utf8.toUtf8(Path), Utf8.toUtf8(LanguageCode), error);

    var privateKey = "Error";
    if (Filecoin.errorCode(error) != 0) {
      stderr.write(Filecoin.errorMessage(error));
    }
    else {
      var privateKeyPtr = Filecoin.extendedKeyPrivateKey(extendedKey, error);
      privateKey = Utf8.fromUtf8(privateKeyPtr);
      assert(privateKey == 'f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a');
      Filecoin.stringFree(privateKeyPtr);
    }

    Filecoin.extendedKeyFree(extendedKey);
    Filecoin.errorFree(error);

    return privateKey;
  }

  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Filecoin'),
        ),
        body: Center(
          child: Text('PrivateKey for Mnemonic "$Mnemonic" and Path "$Path": ${_privateKey()}'),
        ),
      ),
    );
  }
}
