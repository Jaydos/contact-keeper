export default (state, action) => {
  switch (action.type) {
    case 'ADD_CONTACT':
      return {
        ...state,
        contacts: [...state.contacts, action.payload]
      };
    case 'UPDATE_CONTACT':
      return {
        ...state,
        contacts: state.contacts.map(contact =>
          contact.id === action.payload.id ? action.payload : contact
        )
      };
    case 'DELETE_CONTACT':
      return {
        ...state,
        contacts: state.contacts.filter(
          contact => contact.id !== action.payload
        )
      };
    case 'SET_CURRENT':
      return {
        ...state,
        current: action.payload
      };
    case 'CLEAR_CURRENT':
      return {
        ...state,
        current: null
      };
    case 'CLEAR_FILTER':
      return {
        ...state,
        filtered: null
      };
    case 'FILTER_CONTACTS':
      return {
        ...state,
        filtered: state.contacts.filter(
          contact =>
            contact.name.toLowerCase().includes(action.payload.toLowerCase()) ||
            contact.email.includes(action.payload.toLowerCase())
        )
      };
    default:
      return state;
  }
};
