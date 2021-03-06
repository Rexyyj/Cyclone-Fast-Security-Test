// Copyright 2016 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*!
 * @file HelloWorld.cpp
 * This source file contains the definition of the described types in the IDL file.
 *
 * This file was generated by the tool gen.
 */

#ifdef _WIN32
// Remove linker warning LNK4221 on Visual Studio
namespace {
char dummy;
}  // namespace
#endif  // _WIN32

#include "HelloWorld.h"
#include <fastcdr/Cdr.h>

#include <fastcdr/exceptions/BadParamException.h>
using namespace eprosima::fastcdr::exception;

#include <utility>

HelloWorldData::Msg::Msg()
{
    // m_userID com.eprosima.idl.parser.typecode.PrimitiveTypeCode@51b279c9
    m_userID = 0;
    // m_message com.eprosima.idl.parser.typecode.StringTypeCode@1cab0bfb
    m_message ="";

}

HelloWorldData::Msg::~Msg()
{


}

HelloWorldData::Msg::Msg(
        const Msg& x)
{
    m_userID = x.m_userID;
    m_message = x.m_message;
}

HelloWorldData::Msg::Msg(
        Msg&& x)
{
    m_userID = x.m_userID;
    m_message = std::move(x.m_message);
}

HelloWorldData::Msg& HelloWorldData::Msg::operator =(
        const Msg& x)
{

    m_userID = x.m_userID;
    m_message = x.m_message;

    return *this;
}

HelloWorldData::Msg& HelloWorldData::Msg::operator =(
        Msg&& x)
{

    m_userID = x.m_userID;
    m_message = std::move(x.m_message);

    return *this;
}

size_t HelloWorldData::Msg::getMaxCdrSerializedSize(
        size_t current_alignment)
{
    size_t initial_alignment = current_alignment;


    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);


    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;


    return current_alignment - initial_alignment;
}

size_t HelloWorldData::Msg::getCdrSerializedSize(
        const HelloWorldData::Msg& data,
        size_t current_alignment)
{
    (void)data;
    size_t initial_alignment = current_alignment;


    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);


    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.message().size() + 1;


    return current_alignment - initial_alignment;
}

void HelloWorldData::Msg::serialize(
        eprosima::fastcdr::Cdr& scdr) const
{

    scdr << m_userID;
    scdr << m_message;

}

void HelloWorldData::Msg::deserialize(
        eprosima::fastcdr::Cdr& dcdr)
{

    dcdr >> m_userID;
    dcdr >> m_message;
}

/*!
 * @brief This function sets a value in member userID
 * @param _userID New value for member userID
 */
void HelloWorldData::Msg::userID(
        int32_t _userID)
{
    m_userID = _userID;
}

/*!
 * @brief This function returns the value of member userID
 * @return Value of member userID
 */
int32_t HelloWorldData::Msg::userID() const
{
    return m_userID;
}

/*!
 * @brief This function returns a reference to member userID
 * @return Reference to member userID
 */
int32_t& HelloWorldData::Msg::userID()
{
    return m_userID;
}

/*!
 * @brief This function copies the value in member message
 * @param _message New value to be copied in member message
 */
void HelloWorldData::Msg::message(
        const std::string& _message)
{
    m_message = _message;
}

/*!
 * @brief This function moves the value in member message
 * @param _message New value to be moved in member message
 */
void HelloWorldData::Msg::message(
        std::string&& _message)
{
    m_message = std::move(_message);
}

/*!
 * @brief This function returns a constant reference to member message
 * @return Constant reference to member message
 */
const std::string& HelloWorldData::Msg::message() const
{
    return m_message;
}

/*!
 * @brief This function returns a reference to member message
 * @return Reference to member message
 */
std::string& HelloWorldData::Msg::message()
{
    return m_message;
}

size_t HelloWorldData::Msg::getKeyMaxCdrSerializedSize(
        size_t current_alignment)
{
    size_t current_align = current_alignment;


     current_align += 4 + eprosima::fastcdr::Cdr::alignment(current_align, 4);

     


    return current_align;
}

bool HelloWorldData::Msg::isKeyDefined()
{
    return true;
}

void HelloWorldData::Msg::serializeKey(
        eprosima::fastcdr::Cdr& scdr) const
{
    (void) scdr;
     scdr << m_userID;
       
}

