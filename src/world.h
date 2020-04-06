#ifndef WORLD_H
#define WORLD_H

#include "math.h"

#include "hashrecord.h"
#include "stretchyarray.h"

typedef enum LootItemRarity
{
    LOOT_ITEM_RARITY_COMMON = 0x1,
    LOOT_ITEM_RARITY_RARE = 0x2,
    LOOT_ITEM_RARITY_SUPER_RARE = 0x4,
    LOOT_ITEM_RARITY_NOT_EXIST = 0x8
} LootItemRarity;

typedef struct LootItem
{
    unsigned char *id;
    unsigned char *name;
    uint32_t value;
    bool lootable;
    LootItemRarity rarity;
    unsigned char *bundle_path;
} LootItem;

typedef struct LootEntry
{
	Vector3 pos;
	char *name;
	uint32_t value;
	bool container;
	LootItemRarity rarity;
	char *bundle_path;
} LootEntry;

typedef enum ObserverType
{
	OBSERVER_TYPE_NONE = 0,
	OBSERVER_TYPE_SELF,
	OBSERVER_TYPE_PLAYER,
	OBSERVER_TYPE_SCAV
} ObserverType;

typedef struct Inventory
{
	LootEntry *data;
	size_t size;
} Inventory;

typedef enum ObserverFlags
{
	OBSERVER_FLAG_DEAD = 0x1,
	OBSERVER_FLAG_NPC = 0x2,
	OBSERVER_FLAG_UNSPAWNED = 0x4
} ObserverFlags;

typedef struct Observer
{
	uint32_t PID;
	uint8_t CID;
	char *ID, *groupID, *name;
	uint32_t level;

	Vector3 lastPos, currPos; // p0 is last pos, while p1 is current
	Quaternion rot;

	ObserverType type;
	ObserverFlags flags : 3;
	Inventory inventory;
} Observer;

void ZeroObserver(Observer *obs);

typedef struct TemporaryLoot { uint32_t ID; Vector3 pos; } TemporaryLoot;

typedef struct World
{
	Vector3 min, max;
	HashRecord observers; // std::unordered_map<uint8_t, Observer>
	HashRecord temporaryLoot; // std::unordered_map<uint32_t, TemporaryLoot>
	StretchyArray loot; // std::vector<LootEntry>
	StretchyArray corpses; // std::vector<Vector3>
	mtx_t mutex;
} World;

static const size_t MAX_OBSERVERS = (256); // Max possible value of uint8_t
static const size_t MAX_TEMPORARY_LOOT = (4096);

void InitializeWorld(World *world, const Vector3 *min, const Vector3 *max);

void WorldCreateObserver(World *world, uint8_t CID, const Observer *obs);

void WorldDestroyObserver(World *world, uint8_t CID);

#endif // WORLD_H