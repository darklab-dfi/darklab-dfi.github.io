import Api from '@/services/Api'

export default{
    getOutput(clientInfo){
        return Api().post('output', clientInfo)
    }
}
