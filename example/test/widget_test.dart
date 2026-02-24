import 'package:flutter_test/flutter_test.dart';
import 'package:m_security_example/main.dart';

void main() {
  testWidgets('App builds without error', (WidgetTester tester) async {
    await tester.pumpWidget(const ExampleApp());
    expect(find.text('M-Security initialized'), findsOneWidget);
  });
}
