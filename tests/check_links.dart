import 'dart:convert';
import 'dart:io';
import 'package:fcxray/services/config_builder.dart';
import 'package:fcxray/services/profile_importer.dart';

Future<void> main() async {
  final links = jsonDecode(await stdin.transform(utf8.decoder).join()) as List;
  final configs = links.map((link) {
    final profile = ProfileImporter.parse(link as String).single;
    return ConfigBuilder.build(profile, platform: 'macos', mode: ConnectionMode.proxy);
  }).toList();
  stdout.write(jsonEncode(configs));
}
