import 'package:flutter/material.dart';
import 'SplashScreen/splash_screen.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'KavachX Bharat',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFFD98E04),
          brightness: Brightness.dark,
        ),
        scaffoldBackgroundColor: const Color(0xFF101B2D),
        useMaterial3: true,
      ),
      home: const SplashScreen(),
      routes: {
        '/onboarding': (context) => const OnboardingPlaceholderScreen(),
      },
    );
  }
}

class OnboardingPlaceholderScreen extends StatelessWidget {
  const OnboardingPlaceholderScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF101B2D),
      appBar: AppBar(
        title: const Text('KavachX Bharat'),
        backgroundColor: const Color(0xFF101B2D),
        elevation: 0,
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.05),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: const Color(0xFFD98E04),
                    width: 2,
                  ),
                ),
                child: const Icon(
                  Icons.shield_outlined,
                  size: 64,
                  color: Color(0xFFD98E04),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Welcome to KavachX Bharat',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 12),
              const Text(
                'Splash screen completed successfully!\nYou can build your Onboarding / Home screen here.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white70,
                  fontSize: 14,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
