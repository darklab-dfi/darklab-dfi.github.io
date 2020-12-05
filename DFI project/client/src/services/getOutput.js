import Api from '@/services/Api'

export default{
    getOutS11(clientInfo){
        return Api().post('outS11', clientInfo)
    }
}
