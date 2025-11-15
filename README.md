
## Build
```bash
make
```
This produces the executable at `build/exec`.

## Run
```bash
./build/exec
```

## Usage

The program is an interactive demo of the MT-iVRF (Merkle Tree - iterative Verifiable Random Function) implementation. When you run it:

1. You'll be prompted to select parameter mode:
   - Random N and t (default)
   - Manual N and t (you specify values)

2. The program generates key pairs and displays the Merkle root

3. From the main menu, you can:
   - Evaluate VRF: Generate verifiable random outputs by entering:
     - μ₁ and μ₂ messages (hex or ASCII)
     - Round index i (between 0 and N-1)
     - Iteration index j (between 0 and t-1) 
   - Regenerate keys
   - Exit the program

4. The program displays verification results with detailed proof components

You can modify parameters in `ivrf.hpp` (default: N=256, t=4) for different security levels or performance characteristics.

## Clean
```bash
make clean
```

