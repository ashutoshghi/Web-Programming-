import { useEffect, useState } from "react";

function UserList() {
    const [users, setUsers] = useState([]);

    useEffect(() => {
        fetch("http://127.0.0.1:8000/users")
            .then((res) => res.json())
            .then((data) =>{
                setUsers(data)
            }
        )
    }, []);

    return (
        <div className="p-8 bg-amber min-h-screen">
            <div className="overflow-x-auto shadow-lg rounded-l">
                <table className="w-full border-collapse bg-black">
                    <thead>
                        <tr className="bg-gradient-to-r from-blue-600 to-blue-700 text-white">
                            {users.length > 0 &&
                                Object.keys(users[0]).map((key) => (
                                    <th 
                                        key={key} 
                                        className="px-6 py-4 text-left font-semibold text-sm uppercase tracking-wide"
                                    >
                                        {key}
                                    </th>
                                ))}
                        </tr>
                    </thead>

                    <tbody>
                        {users.map((user, index) => (
                            <tr 
                                key={index}
                                className="border-b border-gray-200"
                            >
                                {Object.values(user).map((value, i) => (
                                    <td 
                                        key={i} 
                                        className="px-6 py-4 text-white text-sm"
                                    >
                                        {value}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default UserList;
