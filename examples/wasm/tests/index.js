// `tests` is a singleton variable that will contain all our tests
var tests = [];
var errorsCount = 0;

// The test function accepts a name and a function
function test(name, fn) {
	// it pushes the name and function as an object to
	// the `tests` array
	tests.push({ name, fn });
}

function run() {
	// `run` runs all the tests in the `tests` array
	tests.forEach(t => {
		// For each test, we try to execute the
		// provided function.
		try {
			t.fn();
			// If there is no exception
			// that means it ran correctly
			console.log('\x1b[32m✔', t.name, '\x1b[0m');
		} catch (e) {
			// Exceptions, if any, are caught
			// and the test is considered failed
			console.log('\x1b[31m✗\x1b[0m  \x1b[41m', t.name, '\x1b[49m');
			// log the stack of the error
			console.error('\x1b[31m', e.stack, '\x1b[0m');

      errorsCount = errorsCount + 1;
		}
	})

  if (errorsCount > 0) process.exit(1);
}

// Get the list of files from the command line
// arguments
const files = process.argv.slice(2);

// expose the test function as a global variable
global.test = test;

// Load each file using `import`
for (let index in files) {
  console.log(files[index])
  // Once a file is loaded, it's tests are
	// added to the `tests` singleton variable
	require(files[index]);
}

// Once that all the tests from all the files are
// added, run them one after the other
run();
