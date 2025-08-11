#!/bin/bash
# Documentation generation script for NetTest

set -e

echo "🚀 Generating NetTest Documentation..."

# Clean previous docs
echo "🧹 Cleaning previous documentation..."
rm -rf target/doc

# Generate documentation with all features
echo "📚 Generating API documentation..."
cargo doc --no-deps --document-private-items --all-features

# Run doc tests to ensure examples work
echo "🧪 Running documentation tests..."
cargo test --doc

# Run integration test examples
echo "🔧 Running integration test examples..."
cargo test --test integration_examples

echo "✅ Documentation generation complete!"
echo ""
echo "📖 View documentation:"
echo "  - Open: target/doc/nettest/index.html"
echo "  - Or run: cargo doc --open"
echo ""
echo "🧪 Test documentation examples:"
echo "  - Doc tests: cargo test --doc"
echo "  - Integration: cargo test --test integration_examples"
echo ""
echo "📊 Documentation statistics:"
find target/doc/nettest -name "*.html" | wc -l | xargs echo "  HTML files generated:"
du -sh target/doc/nettest | echo "  Total size: $(cut -f1)"