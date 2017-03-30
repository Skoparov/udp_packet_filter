#ifndef TESTS_HELPERS
#define TESTS_HELPERS

#include <stdexcept>

#define TEST_NAME __FUNCTION__

namespace tests
{


enum class THROW_COND
{
    SHOULD_THROW,
    SHOULD_NOT_THROW
};

namespace details
{

void CHECK_THROW_COND( const THROW_COND& cond, const std::string& testname, const std::string& error );

}

class test_error : public std::runtime_error{ using std::runtime_error::runtime_error; };

void TEST_ASSERT( bool val, const std::string& error )
{
    if( !val )
    {
        throw test_error( error );
    }
}

std::string ERR_MSG( const std::string& testname, const std::string err_msg )
{
    return { testname + " failed: " + err_msg };
}

template< typename Func, typename... Args >
void TEST_EXEC_FUNC( const std::string& testname, const THROW_COND& cond, Func&& f, Args&&... args )
{
    try
    {
        f( std::forward< Args >( args )... );
    }
    catch( const std::exception& e )
    {
        details::CHECK_THROW_COND( cond, testname, e.what() );
    }
}

template< typename Func, typename... Args >
typename std::result_of< Func( Args... ) >::type
TEST_EXEC_FUNC_RESULT( const std::string& testname, const THROW_COND& cond, Func&& f, Args&&... args )
{
    try
    {
        return f( std::forward< Args >( args )... );
    }
    catch( const std::exception& e )
    {
        details::CHECK_THROW_COND( cond, testname, e.what() );
    }
}

namespace details
{

void CHECK_THROW_COND( const THROW_COND& cond, const std::string& testname, const std::string& error )
{
    if( cond == THROW_COND::SHOULD_NOT_THROW )
    {
        throw test_error{ ERR_MSG( testname, error ) };
    }
}

}// details

}// tests

#endif
