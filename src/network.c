#include "network.h"

static Observer DeserializeObserver(ByteStream *stream)
{
	Observer obs = { 0 };

	uint8_t unk2 = ByteStreamReadUInt8(stream);
	uint8_t unk3 = ByteStreamReadBool(stream);

	obs.currPos = ByteStreamReadVector3(stream);
	obs.rot = ByteStreamReadQuaternion(stream);

	obs.inProne = ByteStreamReadBool(stream);
	obs.poseLevel = ByteStreamReadFloat(stream);

	{
		// Parse through gear items
		uint16_t itemsZippedSize;
		const uint8_t *itemsZippedJSON = ByteStreamReadBytes16(stream, &itemsZippedSize);

		// TODO: CSharpByteStream shit
	}

	return obs;
}

static void ProcessServerInit(World *world, ByteStream *stream)
{
	uint8_t unk0 = ByteStreamReadByte(stream);
	uint64_t realDateTime = ByteStreamReadBool(stream) ? 0 : ByteStreamReadUInt64(stream);
	uint64_t gameDateTime = ByteStreamReadInt64(stream);
	float timeFactor = ByteStreamReadFloat(stream);

	{
		// ASSET BUNDLES TO LOAD?
		// json
		uint8_t *unk1 = ByteStreamReadBytes16(stream, NULL);
	}

	{
		// WEATHER?
		// json
		uint8_t *unk2 = ByteStreamReadBytes16(stream, NULL);
	}

	bool unk3 = ByteStreamReadBool(stream);
	uint32_t memberType = ByteStreamReadUInt32(stream); // see EMemberCategory
	float unk4 = ByteStreamReadFloat(stream); // dt?

	{
		// List of lootables? (no locations yet)
		// json
		uint8_t *unk5 = ByteStreamReadBytes16(stream, NULL);
	}

	uint8_t *unk6 = ByteStreamReadBytes16(stream, NULL);

	{
		// GClass806.SetupPositionQuantizer(@class.response.bounds_0);
		Vector3 boundMin = ByteStreamReadVector3(stream);
		Vector3 boundMax = ByteStreamReadVector3(stream);
		LoadWorld(world, (const Vector3 *)&boundMin, (const Vector3 *)&boundMax);
	}

	uint16_t unk7 = ByteStreamReadUInt16(stream);
	uint8_t unk8 = ByteStreamReadByte(stream);
}

static void ProcessWorldSpawn(World *world, ByteStream *stream)
{
	
}

static void ProcessWorldUnspawn(World *world, ByteStream *stream)
{

}

static void ProcessSubworldSpawn(World *world, ByteStream *stream)
{
	
}

static void ProcessSubworldUnspawn(World *world, ByteStream *stream)
{

}

static void ProcessPlayerSpawn(World *world, ByteStream *stream)
{
	uint32_t PID = ByteStreamReadUInt32(stream);
	uint8_t CID = ByteStreamReadUInt8(stream);
	Vector3 pos = ByteStreamReadVector3(stream);
	Observer obs = DeserializeObserver(stream);
	obs.PID = PID;
	obs.CID = CID;
	WorldCreateObserver(world, CID, (const Observer *)&obs);
}

static void ProcessPlayerUnspawn(World *world, ByteStream *stream)
{

}

static void ProcessObserverSpawn(World *world, ByteStream *stream)
{

}

static void ProcessObserverUnspawn(World *world, ByteStream *stream)
{

}

static void ProcessGameUpdate(World *world, ByteStream *stream, uint8_t channelID)
{
	
}

static void ProcessGameUpdateOutbound(World *world, ByteStream *stream, uint8_t channelID)
{

}

void ProcessActions(World *world, ByteStream *stream, uint8_t channelID, bool outbound)
{
	size_t head = 0;

	while (ByteStreamRemaining(stream))
	{
		uint16_t len = ByteStreamReadUInt16(stream);
		ActionCode ac = (ActionCode)ByteStreamReadUInt16(stream);

		const char *codeString = ActionCodeToString(ac);
		//printf("Processing action with code: 0x%04hX (%s)\n", ac, codeString);

		if (IsActionStringUnknown(codeString))
		{
			// Unknown action code
		}
		else
		{
			printf("Processing action with code: 0x%04hX (%s)\n", (uint16_t)ac, codeString);  
		}

		if (outbound)
		{
			// Only care about 170 for outbound local player updates.
			if (ac == ACTION_CODE_GAME_UPDATE)
			{
				// Process game update outbound
				ProcessGameUpdateOutbound(world, stream, channelID);
			}
		}
		else
		{
			switch (ac)
			{
				case ACTION_CODE_SERVER_INIT: ProcessServerInit(world, stream); break;
				case ACTION_CODE_WORLD_SPAWN: ProcessWorldSpawn(world, stream); break;
				case ACTION_CODE_WORLD_UNSPAWN: ProcessWorldUnspawn(world, stream); break;
				case ACTION_CODE_SUBWORLD_SPAWN: ProcessSubworldSpawn(world, stream); break;
				case ACTION_CODE_SUBWORLD_UNSPAWN: ProcessSubworldUnspawn(world, stream); break;
				case ACTION_CODE_PLAYER_SPAWN: ProcessPlayerSpawn(world, stream); break;
				case ACTION_CODE_PLAYER_UNSPAWN: ProcessPlayerUnspawn(world, stream); break;
				case ACTION_CODE_OBSERVER_SPAWN: ProcessObserverSpawn(world, stream); break;
				case ACTION_CODE_OBSERVER_UNSPAWN: ProcessObserverUnspawn(world, stream); break;
				case ACTION_CODE_BATTLE_EYE: break; // Ignored
				case ACTION_CODE_GAME_UPDATE: ProcessGameUpdate(world, stream, channelID); break;
				default: break; // Unknown
			}
		}

		head += len + 4; // 4 is 2 * sizeof(uint16_t)
		ByteStreamSeek(stream, head);
	}
}