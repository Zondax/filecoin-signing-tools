// A dependency graph that contains any wasm must all be imported
// asynchronously. This `bootstrap.js` file does the single async import
import('./index.js')
  .catch(e => console.error('Error importing `index.js`:', e))
  .then( ()=> {
    import('./index-multisig.js')
  })
  .catch(e => console.error('Error importing `index-multisig.js`:', e))
