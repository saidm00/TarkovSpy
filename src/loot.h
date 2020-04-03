#ifndef LOOT_H
#define LOOT_H

/*
#include "hash_map.h"
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

typedef struct LootDataBase
{
    hash_map_t map;
} LootDataBase;

void SetupLootDataBase(LootDataBase *db, const char *path);
const LootItem *QueryLoot(LootDataBase *db, const char *id);
*/

#endif // LOOT_H
