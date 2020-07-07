module.exports = {
    base: '/filecoin-signing-tools/',
    title: 'Filecoin Signing Tools',
    description: 'Services and Libraries ',

    themeConfig: {
      nav: [
        { text: 'Home', link: '/' },
        { text: 'Documentation', link: '/Main.md' },
        { text: 'About Zondax', link: 'https://zondax.ch' },
      ],
      sidebar: [
        {
          title: 'JSON RPC',   // required
          path: '/jsonrpc/',      // optional, which should be a absolute path.
          collapsable: false, // optional, defaults to true
          sidebarDepth: 2,    // optional, defaults to 1
          children: [
            '/jsonrpc/',
            '/jsonrpc/api',
            '/jsonrpc/workflow'
          ]
        },
        {
          title: 'WASM',
          path: '/wasm/',
          collapsable: false, // optional, defaults to true
          sidebarDepth: 2,    // optional, defaults to 1
          children: [
            '/wasm/',
            '/wasm/api',
            '/wasm/ledger'
          ]
        },
        {
          title: 'Native',
          path: '/native/',
          collapsable: false, // optional, defaults to true
          sidebarDepth: 2,    // optional, defaults to 1
          children: [
            '/native/',
            '/native/api'
          ]
        }
    ]
    }
}
