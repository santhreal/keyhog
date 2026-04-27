# Contributing to Keyhog

First off, thank you for considering contributing to Keyhog! It's people like you that make Keyhog such a great tool. 

This document provides a set of guidelines and instructions for contributing to the project.

## 1. How to add a new detector

Adding a new detector is trivially easy and requires no Rust code. All detectors are defined as TOML files in the `detectors/` directory.

1. Copy an existing TOML file in the `detectors/` directory. For example:
   ```bash
   cp detectors/stripe-secret-key.toml detectors/my-new-service-key.toml
   ```
2. Open your new `my-new-service-key.toml` file and fill in the required fields:
   - `id`: A unique identifier for the detector (e.g., `my-new-service-key`).
   - `name`: A human-readable name.
   - `pattern`: The regex pattern used to detect the secret.
   - `keywords`: A list of keywords that help pre-filter the search.
   - `confidence`: The confidence level of the regex (`high`, `medium`, `low`).
3. Run the validation script to ensure your new detector is correctly formatted:
   ```bash
   cargo test --package keyhog-core --test detector_validation
   ```

## 2. How to add a new source backend

To add a new source backend (e.g., a new version control system or cloud storage provider), you need to implement the `Source` trait.

1. Navigate to the `crates/sources/src/` directory.
2. Create a new module for your source backend.
3. Implement the `keyhog_core::Source` trait for your new backend. This typically involves implementing methods to iterate over files or data streams.
4. Register your new source in the main `keyhog` application so it can be invoked via the command line.
5. Add appropriate unit and integration tests for your source.

## 3. How to add a new output format

To add a new output format (e.g., a new reporting standard like SARIF or a custom JSON structure), you need to implement the `Reporter` trait.

1. Navigate to the `crates/cli/src/reporters/` directory.
2. Create a new module for your output format.
3. Implement the `keyhog_core::Reporter` trait. This trait defines how findings are formatted and written to the output stream.
4. Add your new reporter to the CLI options in `crates/cli/src/args.rs`.
5. Write tests verifying the output format exactly matches the expected schema.

## 4. How to improve the ML model

If you are working on the ML-based secret verification or false-positive reduction, follow these steps:

1. **Generate Data**: Use the provided scripts in the `ml/` directory to generate or curate training data. Ensure you have a balanced dataset of true positives and false positives.
2. **Train**: Run the training pipeline (usually a Python script in `ml/`). 
   ```bash
   cd ml/
   python train.py --dataset path/to/dataset
   ```
3. **Test**: Evaluate the model's precision and recall using the test suite. 
4. **Export**: Export the trained model weights to the format expected by the Rust inference engine and update the model file in the repository.

## 5. How to run tests

We use `make` to simplify running common development tasks.

- **Run all tests**: 
  ```bash
  make test
  ```
- **Run the linter (Clippy)**:
  ```bash
  make clippy
  ```
- **Run benchmarks**:
  ```bash
  make bench
  ```

## 6. Code Style Guide

We strive for Linux-level elegance and strictly follow standard Rust conventions.

- **Import Ordering**: Group imports into `std`, external crates, and internal `crate::` modules.
- **Naming**: 
  - Types use `PascalCase`.
  - Functions and variables use `snake_case`.
  - Constants use `SCREAMING_SNAKE_CASE`.
  - Boolean variables should read as questions (e.g., `is_valid`, `has_findings`).
- **Error Handling**: 
  - Zero `unwrap()` or `expect()` in non-test code.
  - Use `?` for error propagation.
  - Error messages must be lowercase, actionable, and specific.
- **Documentation**: All public items must have doc comments (`///`).

## 7. PR Checklist

Before submitting a Pull Request, please ensure the following:

- [ ] **Tests pass**: Run `make test` and ensure all tests are green.
- [ ] **Clippy clean**: Run `make clippy` and ensure there are zero warnings. We treat warnings as errors.
- [ ] **No rigged tests**: Ensure tests realistically cover the code and aren't just asserting hardcoded values without exercising the logic.
- [ ] **Doc comments**: All new public functions, traits, and types have comprehensive doc comments.
- [ ] **No Stubs**: Ensure all implemented functions perform real work and are not just placeholders.
