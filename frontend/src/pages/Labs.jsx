import { useNavigate, useParams } from 'react-router-dom';
import { useLabs } from '../context/LabContext';
import { LAB_COMPONENTS } from '../components/labs';
import Card from '../components/common/Card';
import EmptyState from '../components/common/EmptyState';

export default function Labs() {
  const { labs, resultFor } = useLabs();
  const { labId } = useParams();
  const nav = useNavigate();

  const activeId = labId ?? labs[0]?.id;
  const active = labs.find((l) => l.id === activeId);

  return (
    <div className="grid" style={{ gridTemplateColumns: 'minmax(260px, 300px) minmax(0, 1fr)' }}>
      <Card title="Lab bench" flush>
        <div>
          {labs.map((lab) => (
            <div key={lab.id} className={`finding-row${lab.id === activeId ? ' is-active' : ''}`}
              role="button" tabIndex={0}
              onClick={() => nav(`/labs/${lab.id}`)}
              onKeyDown={(e) => e.key === 'Enter' && nav(`/labs/${lab.id}`)}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="finding-row__title">{lab.title}</div>
                <div className="finding-row__cat">{lab.findingId}</div>
              </div>
              {resultFor(lab.id)?.exploited && (
                <span className="badge badge--critical">exploited</span>
              )}
            </div>
          ))}
        </div>
      </Card>

      <div>
        {active && LAB_COMPONENTS[active.id]
          ? (() => {
            const Component = LAB_COMPONENTS[active.id];
            return <Component lab={active} />;
          })()
          : <Card><EmptyState message="Lab not found." /></Card>}
      </div>
    </div>
  );
}