#include "world.h"

static void ZeroInventory(Inventory *inv)
{
	inv->data = NULL;
	inv->size = 0;
}

void ZeroObserver(Observer *obs)
{
	obs->PID = 0;
	obs->CID = 0;
	obs->ID = NULL;
	obs->groupID = NULL;
	obs->name = NULL;
	obs->level = 0;
	obs->lastPos = (Vector3){ 0.0f, 0.0f, 0.0f };
	obs->currPos = (Vector3){ 0.0f, 0.0f, 0.0f };
	obs->rot = (Quaternion){ 0.0f, 0.0f, 0.0f, 0.0f };
	obs->flags = 0;
	obs->type = OBSERVER_TYPE_NONE;
	ZeroInventory(&obs->inventory);
}

void InitializeWorld(World *world)
{	
	InitializeHashRecord(&world->observers, MAX_OBSERVERS,
		sizeof(uint8_t) /* CID */, sizeof(Observer));

	InitializeHashRecord(&world->temporaryLoot, MAX_TEMPORARY_LOOT,
		sizeof(uint32_t) /* ID */, sizeof(TemporaryLoot));

	InitializeStretchyArray(&world->loot, sizeof(LootEntry));
	InitializeStretchyArray(&world->corpses, sizeof(Vector3));

	mtx_init(&world->mutex, mtx_plain);

	world->isLoaded = false;
}

void LoadWorld(World *world, const Vector3 *min, const Vector3 *max)
{
	world->isLoaded = true;
	world->min = *min;
	world->max = *max;
}

void WorldCreateObserver(World *world, uint8_t CID, const Observer *obs)
{
	mtx_lock(&world->mutex);

	HashKey key = (HashKey) { 1, (void *)&CID };
	uint64_t index = HashRecordQueryIndex(&world->observers, &key);

	if (!HashRecordQueryExistsByIndex(&world->observers, index))
	{
		// Observer doesn't yet exist at CID slot, emplace it
		HashRecordInsertByIndex(&world->observers, index, obs);
	}
	else
	{
		// Observer already at CID slot
	}

	mtx_unlock(&world->mutex);
}

void WorldDestroyObserver(World *world, uint8_t CID)
{
	// TODO: HashRecord doesn't have remove function yet
}