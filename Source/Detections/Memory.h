#pragma once

namespace Vicra {
class MemoryDetection : public IPlugin {
private:
	struct IntegrityMapping_t {
		DWORD64 First8Bytes;
		LPCSTR FunctionName;
	};

private:
	std::unordered_map<SHORT, LPCSTR> m_SystemCallNumberMappings {};
	std::unordered_map<DWORD64, IntegrityMapping_t> m_FunctionByteMappings {};

private:
	VOID CreateMappings( );

private:
	SHORT m_DirectoryTableBaseOffset = 0x28;

public:
	VOID Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) override;
};
}
