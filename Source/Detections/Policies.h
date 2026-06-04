#pragma once

namespace Vicra {
class PolicyDetection : public IPlugin {
private:
	SHORT m_Flags3Offset = NULL;

private:
	VOID ResolveOffsets( const std::shared_ptr< Driver >& Driver );

public:
	VOID Run( const std::shared_ptr< Process >& Process, const std::shared_ptr< Driver >& Driver, const USHORT& Verdict ) override;
};
}