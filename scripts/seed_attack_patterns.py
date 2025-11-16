#!/usr/bin/env python3
"""
Seed attack patterns database from JSON templates.

This script loads attack patterns from the templates directory
and populates the database.
"""
import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select

from backend.core.database import AsyncSessionLocal, init_db
from backend.core.models import AttackPattern


async def load_patterns_from_json(file_path: Path) -> list[dict]:
    """Load attack patterns from JSON file."""
    with open(file_path, "r") as f:
        return json.load(f)


async def seed_attack_patterns():
    """Seed attack patterns into database."""
    print("🌱 Seeding attack patterns...")

    # Initialize database
    await init_db()

    # Load patterns from JSON
    templates_dir = Path(__file__).parent.parent / "backend" / "redteam" / "templates"
    patterns_file = templates_dir / "injection_patterns.json"

    if not patterns_file.exists():
        print(f"❌ Pattern file not found: {patterns_file}")
        return

    patterns_data = await load_patterns_from_json(patterns_file)
    print(f"📄 Loaded {len(patterns_data)} patterns from {patterns_file.name}")

    # Insert patterns
    async with AsyncSessionLocal() as session:
        created_count = 0
        updated_count = 0

        for pattern_data in patterns_data:
            # Check if pattern already exists
            result = await session.execute(
                select(AttackPattern).where(
                    AttackPattern.name == pattern_data["name"]
                )
            )
            existing_pattern = result.scalar_one_or_none()

            if existing_pattern:
                # Update existing pattern
                existing_pattern.technique = pattern_data["technique"]
                existing_pattern.category = pattern_data["category"]
                existing_pattern.description = pattern_data.get("description")
                existing_pattern.template = pattern_data["template"]
                existing_pattern.variables = pattern_data.get("variables")
                existing_pattern.severity = pattern_data.get("severity", "medium")
                existing_pattern.owasp_category = pattern_data.get("owasp_category")
                existing_pattern.mitre_atlas_id = pattern_data.get("mitre_atlas_id")
                existing_pattern.target_models = pattern_data.get("target_models")
                existing_pattern.tags = pattern_data.get("tags")
                existing_pattern.is_active = True

                updated_count += 1
                print(f"  ✏️  Updated: {pattern_data['name']}")

            else:
                # Create new pattern
                pattern = AttackPattern(
                    name=pattern_data["name"],
                    technique=pattern_data["technique"],
                    category=pattern_data["category"],
                    description=pattern_data.get("description"),
                    template=pattern_data["template"],
                    variables=pattern_data.get("variables"),
                    severity=pattern_data.get("severity", "medium"),
                    owasp_category=pattern_data.get("owasp_category"),
                    mitre_atlas_id=pattern_data.get("mitre_atlas_id"),
                    target_models=pattern_data.get("target_models"),
                    tags=pattern_data.get("tags"),
                    is_active=True,
                )

                session.add(pattern)
                created_count += 1
                print(f"  ✅ Created: {pattern_data['name']}")

        await session.commit()

    print(f"\n✨ Seeding complete!")
    print(f"   Created: {created_count} patterns")
    print(f"   Updated: {updated_count} patterns")
    print(f"   Total: {created_count + updated_count} patterns")


if __name__ == "__main__":
    asyncio.run(seed_attack_patterns())
