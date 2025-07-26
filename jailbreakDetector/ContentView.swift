//
//  ContentView.swift
//  jailbreakDetector
//
//  Created by setuper on 17.05.2025.
//

import SwiftUI

struct ContentView: View {
    @State private var isJailbroken = "I dont know"
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text(isJailbroken)
        }
        .onAppear {
            isJailbroken = "\(JailbreakDetector.isDeviceJailbroken())"
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
