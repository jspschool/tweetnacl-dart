import 'package:tweetnacl/tweetnacl.dart';
import "dart:convert";
import 'dart:typed_data';

void testSignDetached(String seedStr) {
  print("seed:@${DateTime.now().millisecondsSinceEpoch}");

  List<int> seed = TweetNaclFast.hexDecode(seedStr);
  KeyPair kp = Signature.keyPair_fromSeed(seed);

  String testString = "test string";
  Uint8List bytes = utf8.encode(testString);

  Signature s1 = Signature(null, kp.secretKey);
  print("\ndetached...@${DateTime.now().millisecondsSinceEpoch}");
  Uint8List signature = s1.detached(bytes);
  print("...detached@${DateTime.now().millisecondsSinceEpoch}");

  Signature s2 = Signature(kp.publicKey, null);
  print("\nverify...@${DateTime.now().millisecondsSinceEpoch}");
  bool result = s2.detached_verify(bytes,  signature);
  print("...verify@${DateTime.now().millisecondsSinceEpoch}");

  assert(result == true);
}

void main() {
  testSignDetached("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
  testSignDetached("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
}




